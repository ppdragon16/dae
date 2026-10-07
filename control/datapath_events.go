/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/cilium/ebpf/ringbuf"
	log "github.com/sirupsen/logrus"

	"github.com/daeuniverse/dae/common"
)

// Datapath event types. Keep in sync with enum dae_event_type in
// kern/tproxy.c; the slot key shared with userspace is type*8+site.
const (
	datapathEventUnspecified              uint32 = 0
	datapathEventRoutingTuplesWriteFailed uint32 = 1
	datapathEventRedirectTrackWriteFailed uint32 = 2
	datapathEventCookiePidWriteFailed     uint32 = 3
)

// Site ids used by DAE_EVENT_ROUTING_TUPLES_WRITE_FAILED.
const (
	routingTuplesSiteUdpNewFlow uint32 = 1
	routingTuplesSiteTcpDirect  uint32 = 2
	routingTuplesSiteTcpProxy   uint32 = 3
)

// Slot geometry, mirroring kern/tproxy.c.
const (
	datapathEventSlotTypes = 8
	datapathEventSlotSites = 8
)

const (
	// datapathEventReportInterval is how often the exact counters are sampled
	// into metrics.
	datapathEventReportInterval = 10 * time.Second
	// datapathEventReportWarnInterval rate-limits the per-window volume warning.
	datapathEventReportWarnInterval = 30 * time.Second
)

// datapathEvent mirrors struct dae_event in kern/tproxy.c.
//
// The C side pins sizeof(struct dae_event) == 24 with a compile-time check and
// we decode field by field, so Go's struct padding is irrelevant; only the
// field sizes have to match. TestDatapathEventLayout keeps both ends honest.
type datapathEvent struct {
	TimestampNs uint64
	Type        uint32
	Site        uint32
	Errno       int32
	L4Proto     uint32
}

// datapathEventSlotSize is sizeof(struct dae_event_slot) in kern/tproxy.c.
const datapathEventSlotSize = 24

// datapathEventSlot mirrors struct dae_event_slot in kern/tproxy.c: the exact
// (never throttled) failure count plus the last error seen for that slot.
type datapathEventSlot struct {
	Count       uint64
	LastEmitNs  uint64
	LastErrno   int32
	LastL4Proto uint32
}

// eventSlotDelta reports how many failures are new in this sample. A zero
// previous value means "no baseline yet": the whole count is reported once so a
// map that was already failing stays visible instead of looking quiet.
func eventSlotDelta(previous, current uint64) uint64 {
	if current == 0 {
		return 0
	}
	if previous == 0 {
		return current
	}
	if current <= previous {
		return 0
	}
	return current - previous
}

func datapathSlotKey(eventType, site uint32) uint32 {
	return (eventType%datapathEventSlotTypes)*datapathEventSlotSites + site%datapathEventSlotSites
}

func decodeDatapathEvent(raw []byte) (datapathEvent, error) {
	var ev datapathEvent
	if len(raw) != 24 {
		return ev, fmt.Errorf("unexpected datapath event size %d (want 24)", len(raw))
	}
	ev.TimestampNs = binary.NativeEndian.Uint64(raw[0:8])
	ev.Type = binary.NativeEndian.Uint32(raw[8:12])
	ev.Site = binary.NativeEndian.Uint32(raw[12:16])
	ev.Errno = int32(binary.NativeEndian.Uint32(raw[16:20]))
	ev.L4Proto = binary.NativeEndian.Uint32(raw[20:24])
	return ev, nil
}

func (ev datapathEvent) String() string {
	name := datapathEventTypeName(ev.Type)
	return fmt.Sprintf("%s(site=%d errno=%d l4proto=%d)", name, ev.Site, ev.Errno, ev.L4Proto)
}

func datapathEventTypeName(eventType uint32) string {
	switch eventType {
	case datapathEventRoutingTuplesWriteFailed:
		return "routing_tuples_write_failed"
	case datapathEventRedirectTrackWriteFailed:
		return "redirect_track_write_failed"
	case datapathEventCookiePidWriteFailed:
		return "cookie_pid_write_failed"
	default:
		return fmt.Sprintf("unknown_event_%d", eventType)
	}
}

// datapathEventSink reacts to decoded events on behalf of the control plane
// that is currently serving. It is registered by the active control plane and
// cleared by Close, so a superseded control plane stops receiving events.
type datapathEventSink struct {
	owner   *ControlPlane
	janitor *bpfMapJanitor
}

func (s *datapathEventSink) HandleDatapathEvent(ev datapathEvent) {
	switch ev.Type {
	case datapathEventRoutingTuplesWriteFailed, datapathEventRedirectTrackWriteFailed:
		// A rejected write means a bounded datapath map is under pressure.
		// The periodic janitor can be minutes away; sweep now so the map has a
		// chance to free entries before the next packet needs them. Only the
		// map that failed is forced: the others are 64k-entry scans.
		if s.janitor != nil {
			if ev.Type == datapathEventRedirectTrackWriteFailed {
				s.janitor.WakePressure(janitorPressureRedirect)
			} else {
				s.janitor.WakePressure(janitorPressureRoutingTuples)
			}
		}
		log.WithFields(log.Fields{
			"event":   datapathEventTypeName(ev.Type),
			"site":    ev.Site,
			"errno":   ev.Errno,
			"l4proto": ev.L4Proto,
		}).Warnln("datapath rejected a map write; the affected flows fall back to userspace handling")
	case datapathEventCookiePidWriteFailed:
		// cookie_pid_map full: process-name attribution degrades, routing is
		// unaffected, so do not wake the janitor (it cannot help quickly).
		log.WithFields(log.Fields{
			"event": datapathEventTypeName(ev.Type),
			"site":  ev.Site,
			"errno": ev.Errno,
		}).Warnln("datapath could not record a process-name mapping; pname-based rules may not match")
	default:
		log.WithField("event", ev.String()).Debugln("unhandled datapath event")
	}
}

// datapathEventConsumer owns the process-wide event ring buffer reader.
//
// The ring buffer is a single-consumer queue, and hot reload hands the same
// bpf objects to the new control plane, so ownership follows the bpf state
// rather than the (replaced) control plane: a reload keeps the very same
// reader, and only a fresh bpf load supersedes it. Stopping therefore belongs
// to the bpf state's lifetime, not to ControlPlane.Close.
type datapathEventConsumer struct {
	mu     sync.Mutex
	bpf    *bpfState
	cancel context.CancelFunc
	done   chan struct{}

	// lastCounts holds the previous exact per-slot counts so the reporter can
	// tell "failures in this window" from "failures long ago".
	lastCounts map[uint32]uint64
	// reportWarnAt rate-limits the volume summary.
	reportWarnAt atomic.Int64

	sink atomic.Pointer[datapathEventSink]
}

var datapathEvents datapathEventConsumer

func startDatapathEventConsumer(bpf *bpfState) {
	datapathEvents.start(bpf)
}

// stopDatapathEventConsumer stops the process-wide consumer. Ownership follows
// the bpf state (see datapathEventConsumer), so the caller must know that the
// state is really dying: a reload hands it to a successor that keeps the very
// same reader running.
func stopDatapathEventConsumer() {
	datapathEvents.stop()
}

func setDatapathEventSink(sink *datapathEventSink) {
	datapathEvents.sink.Store(sink)
}

// clearDatapathEventSink unhooks owner only if it is still the registered sink,
// so a closing control plane cannot unhook the successor that a hot reload has
// already installed.
func clearDatapathEventSink(owner *ControlPlane) {
	if cur := datapathEvents.sink.Load(); cur != nil && cur.owner == owner {
		datapathEvents.sink.CompareAndSwap(cur, nil)
	}
}

func (c *datapathEventConsumer) start(bpf *bpfState) {
	if bpf == nil || bpf.EventRingbuf == nil {
		log.Warnln("datapath event ring buffer is unavailable; datapath events will not be reported")
		return
	}

	c.mu.Lock()
	defer c.mu.Unlock()
	if c.bpf == bpf && c.cancel != nil {
		return
	}
	c.stopLocked()

	reader, err := ringbuf.NewReader(bpf.EventRingbuf)
	if err != nil {
		log.WithError(err).Errorln("failed to open the datapath event ring buffer")
		return
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	c.bpf, c.cancel, c.done = bpf, cancel, done
	c.lastCounts = make(map[uint32]uint64)
	c.reportWarnAt.Store(0)
	go c.run(ctx, reader, done)
	go c.report(ctx, bpf)
}

func (c *datapathEventConsumer) stop() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.stopLocked()
}

func (c *datapathEventConsumer) stopLocked() {
	if c.cancel == nil {
		return
	}
	c.cancel()
	select {
	case <-c.done:
	case <-time.After(time.Second):
		log.Warnln("datapath event consumer did not stop in time")
	}
	c.bpf, c.cancel, c.done = nil, nil, nil
}

// report publishes the exact datapath failure counters from event_slots. The
// events themselves are throttled inside the kernel (one per slot per second),
// so they understate the volume on purpose; these counters do not.
func (c *datapathEventConsumer) report(ctx context.Context, bpf *bpfState) {
	ticker := time.NewTicker(datapathEventReportInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
		if bpf.EventSlots == nil {
			return
		}
		c.publishEventSlots(bpf)
	}
}

func (c *datapathEventConsumer) publishEventSlots(bpf *bpfState) {
	if common.Metrics.DatapathEvents == nil {
		return
	}
	var (
		totalDelta uint64
		lastErrno  int32
		lastEvent  uint32
		lastSite   uint32
	)
	for eventType := uint32(1); eventType < datapathEventSlotTypes; eventType++ {
		for site := uint32(0); site < datapathEventSlotSites; site++ {
			key := datapathSlotKey(eventType, site)
			var slot datapathEventSlot
			if err := bpf.EventSlots.Lookup(key, &slot); err != nil {
				continue
			}
			previous := c.lastCounts[key]
			delta := eventSlotDelta(previous, slot.Count)
			if slot.Count == 0 && previous == 0 {
				continue
			}
			c.lastCounts[key] = slot.Count
			labels := [2]string{datapathEventTypeName(eventType), strconv.FormatUint(uint64(site), 10)}
			common.Metrics.DatapathEvents.With2(labels).Set(int64(slot.Count))
			common.Metrics.DatapathEventLastErrno.With2(labels).Set(int64(slot.LastErrno))
			if delta > 0 {
				totalDelta += delta
				lastErrno = slot.LastErrno
				lastEvent = eventType
				lastSite = site
			}
		}
	}
	if totalDelta == 0 {
		return
	}
	// The event path already warns per occurrence; this one adds the volume in
	// the window, so keep it coarse.
	now := time.Now().UnixNano()
	if last := c.reportWarnAt.Load(); now-last > int64(datapathEventReportWarnInterval) &&
		c.reportWarnAt.CompareAndSwap(last, now) {
		log.WithFields(log.Fields{
			"failures": totalDelta,
			"last":     fmt.Sprintf("%s(site=%d)", datapathEventTypeName(lastEvent), lastSite),
			"errno":    lastErrno,
		}).Warnln("datapath map write failures in the last window")
	}
}

func (c *datapathEventConsumer) run(ctx context.Context, reader *ringbuf.Reader, done chan struct{}) {
	defer close(done)
	go func() {
		<-ctx.Done()
		_ = reader.Close()
	}()

	for {
		rec, err := reader.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) || ctx.Err() != nil {
				return
			}
			log.Debugf("failed to read the datapath event ring buffer: %v", err)
			// Do not spin on a persistent error.
			select {
			case <-time.After(100 * time.Millisecond):
			case <-ctx.Done():
				return
			}
			continue
		}
		ev, err := decodeDatapathEvent(rec.RawSample)
		if err != nil {
			log.Debugf("failed to decode a datapath event: %v", err)
			continue
		}
		if sink := c.sink.Load(); sink != nil {
			sink.HandleDatapathEvent(ev)
		}
	}
}
