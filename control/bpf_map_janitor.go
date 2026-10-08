/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"context"
	"errors"
	"os"
	"strings"
	"sync/atomic"
	"time"

	"github.com/cilium/ebpf"
	log "github.com/sirupsen/logrus"
	"golang.org/x/sys/unix"

	"github.com/daeuniverse/dae/common"
)

const (
	// Base tick interval for the janitor goroutine.
	janitorTickInterval = 10 * time.Second
	// Max interval when the janitor is calm (no entries to clean up).
	janitorMaxInterval = 5 * time.Minute

	// cookiePidMap scan and timeout constants.
	cookiePidJanitorInterval = 30 * time.Second
	cookiePidMapTimeout      = 5 * time.Minute

	// redirectTrack scan and timeout constants.
	redirectTrackJanitorInterval = 30 * time.Second
	redirectTrackTimeout         = 1 * time.Minute

	// routingTuples scan and timeout constants.
	routingTuplesJanitorInterval = 30 * time.Second
	// routingTuplesTimeoutActive is how long a live TCP entry may go without a
	// packet before it is dropped. Losing one is not a cache miss: the
	// remaining packets of an established connection whose entry is gone are
	// passed straight through by the datapath instead of re-routed, so the
	// timeout has to outlast the idle periods of connections that are still
	// alive. Application heartbeats are opt-in (OpenSSH's ServerAliveInterval
	// defaults to 0), so two hours is the floor rather than the ceiling.
	routingTuplesTimeoutActive  = 2 * time.Hour
	routingTuplesTimeoutClosing = 10 * time.Second
	routingTuplesTimeoutUdp     = 1 * time.Minute

	janitorBatchLookupSize = 64
	janitorDeleteInitCap   = 32

	// janitorPressureLogInterval rate-limits the report of an urgent sweep: a
	// sustained datapath pressure would otherwise ask for one every second.
	janitorPressureLogInterval = 5 * time.Second
	// janitorPressureSweepInterval is the minimum spacing between urgent
	// sweeps. Under a sustained flood the events arrive once per second per
	// slot, so without this every event would buy a full three-map scan; the
	// request is not dropped, it just waits for the window.
	janitorPressureSweepInterval = time.Second
)

// Pressure categories an urgent sweep may be asked for. An urgent round only
// forces the map that actually rejected a write: sweeping an unaffected map
// would be wasted work, and each one is a 64k-entry scan.
//
// There is deliberately no cookie_pid bit: a full cookie_pid_map degrades
// process-name attribution while routing keeps working, so it is not worth an
// out-of-band sweep (see the sink's cookie_pid case). Its periodic cadence
// still applies.
const (
	janitorPressureRedirect uint32 = 1 << iota
	janitorPressureRoutingTuples
)

// ---- scratch helpers ----

type janitorScratch[K, V any] struct {
	keys   [janitorBatchLookupSize]K
	values [janitorBatchLookupSize]V
	delete []K
}

func recycleScratchDelete[S ~[]E, E any](s *S) {
	// Reuse the backing array across rounds. Shrinking here — even to half the
	// peak — just re-grows on the next heavy round, reallocating every tick.
	// The retained peak is bounded by the number of entries expired in a single
	// round, so keeping it is cheap.
	*s = (*s)[:0]
}

// ---- janitor ----

type bpfMapJanitor struct {
	bpf func() *bpfObjects

	wake chan bool // true=cleanup now, false/closed=stop
	done chan struct{}
	// pressure holds the categories whose map rejected a write (see
	// janitorPressure*). The next round forces exactly those categories past
	// their intervals: the periodic cadence can be minutes away, while the map
	// needs room right now.
	pressure atomic.Uint32
	// pressureWarnAt rate-limits the "pressure but nothing to free" warning.
	pressureWarnAt atomic.Int64
	// pressureLogAt rate-limits the "swept under pressure" report.
	pressureLogAt atomic.Int64
	// pressureSweepAt is when the last urgent sweep started.
	pressureSweepAt      atomic.Int64
	cookiePidScratch     janitorScratch[uint64, bpfPidPname]
	redirectScratch      janitorScratch[bpfRedirectTuple, bpfRedirectEntry]
	routingTuplesScratch janitorScratch[bpfTuplesKey, bpfRoutingResult]
}

func newBpfMapJanitor(bpf func() *bpfObjects) bpfMapJanitor {
	return bpfMapJanitor{
		bpf:  bpf,
		wake: make(chan bool, 1),
		done: make(chan struct{}),
		cookiePidScratch: janitorScratch[uint64, bpfPidPname]{
			delete: make([]uint64, 0, janitorDeleteInitCap),
		},
		redirectScratch: janitorScratch[bpfRedirectTuple, bpfRedirectEntry]{
			delete: make([]bpfRedirectTuple, 0, janitorDeleteInitCap),
		},
		routingTuplesScratch: janitorScratch[bpfTuplesKey, bpfRoutingResult]{
			delete: make([]bpfTuplesKey, 0, janitorDeleteInitCap),
		},
	}
}

// WakePressure asks for an immediate cleanup of kinds (a janitorPressure* mask)
// that also ignores their per-category intervals. It is how a datapath write
// failure (reported over the event ring buffer) turns into an urgent sweep
// instead of a wait of up to janitorMaxInterval.
func (j *bpfMapJanitor) WakePressure(kinds uint32) {
	j.pressure.Or(kinds)
	j.Wake()
}

// janitorPressureNames renders a pressure mask for the log.
func janitorPressureNames(kinds uint32) string {
	if kinds == 0 {
		return "none"
	}
	names := make([]string, 0, 3)
	if kinds&janitorPressureRoutingTuples != 0 {
		names = append(names, "routing_tuples")
	}
	if kinds&janitorPressureRedirect != 0 {
		names = append(names, "redirect_track")
	}
	return strings.Join(names, ",")
}

// reservePressureSweep decides whether a pending urgent sweep may run now, and
// which categories it covers.
//
// It returns the categories to force (and records the time) when the previous
// sweep is at least janitorPressureSweepInterval old, or 0 when it is too soon
// — in which case the request is merged back so a later round honours it
// instead of it being lost. Requests are never dropped, only delayed; requests
// that arrive while this runs stay pending for the next round.
func (j *bpfMapJanitor) reservePressureSweep(nowNano int64) uint32 {
	pending := j.pressure.Swap(0)
	if pending == 0 {
		return 0
	}
	if last := j.pressureSweepAt.Load(); nowNano-last < int64(janitorPressureSweepInterval) {
		j.pressure.Or(pending)
		return 0
	}
	j.pressureSweepAt.Store(nowNano)
	return pending
}

// Wake signals the janitor to perform a cleanup round immediately. Safe
// to call concurrently from any goroutine.
func (j *bpfMapJanitor) Wake() {
	select {
	case j.wake <- true:
	default:
	}
}

func (j *bpfMapJanitor) Start(ctx context.Context) {
	go func() {
		interval := janitorTickInterval
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		defer close(j.done)

		var lastCookiePidCleanup, lastRedirectCleanup, lastRoutingTuplesCleanup time.Time

		for {
			select {
			case shouldCleanup := <-j.wake:
				if !shouldCleanup {
					return
				}
				// External signal (e.g. connection set to CLOSING):
				// run a cleanup round immediately.
			case <-ctx.Done():
				return
			case <-ticker.C:
			}

			now := time.Now()
			cleaned := 0
			// A pressure round forces the categories the datapath complained
			// about past their intervals. Urgent sweeps are spaced out; a
			// request that arrives too soon stays pending.
			pressure := j.reservePressureSweep(now.UnixNano())
			force := pressure != 0
			var freedCookiePid, freedRedirect, freedRoutingTuples int

			if lastCookiePidCleanup.IsZero() || now.Sub(lastCookiePidCleanup) >= cookiePidJanitorInterval {
				n := j.cleanupCookiePidMap()
				freedCookiePid = n
				cleaned += n
				lastCookiePidCleanup = now
			}
			if pressure&janitorPressureRedirect != 0 || lastRedirectCleanup.IsZero() || now.Sub(lastRedirectCleanup) >= redirectTrackJanitorInterval {
				n := j.cleanupRedirectTrackMap()
				freedRedirect = n
				cleaned += n
				lastRedirectCleanup = now
			}
			if pressure&janitorPressureRoutingTuples != 0 || lastRoutingTuplesCleanup.IsZero() || now.Sub(lastRoutingTuplesCleanup) >= routingTuplesJanitorInterval {
				n := j.cleanupRoutingTuplesMap()
				freedRoutingTuples = n
				cleaned += n
				lastRoutingTuplesCleanup = now
			}

			if force {
				// Make the proactive sweep observable: without this a pressure
				// round that does free entries leaves no trace in the log at
				// all, and "did the reaction work?" cannot be answered.
				nowNano := now.UnixNano()
				if last := j.pressureLogAt.Load(); nowNano-last > int64(janitorPressureLogInterval) &&
					j.pressureLogAt.CompareAndSwap(last, nowNano) {
					log.WithFields(log.Fields{
						"forced": janitorPressureNames(pressure),
						// Freed by this round: the forced categories plus
						// any whose periodic interval happened to elapse.
						"routing_tuples": freedRoutingTuples,
						"redirect_track": freedRedirect,
						"cookie_pid":     freedCookiePid,
						"total":          cleaned,
					}).Infoln("datapath pressure: swept the maps immediately")
				}
			} else if cleaned > 0 && log.IsLevelEnabled(log.DebugLevel) {
				// Periodic rounds are frequent and normally free idle flows;
				// keep them out of the default log. The level check comes
				// first so the field map is not built when nothing is emitted.
				log.WithFields(log.Fields{
					"routing_tuples": freedRoutingTuples,
					"redirect_track": freedRedirect,
					"cookie_pid":     freedCookiePid,
				}).Debugln("janitor swept the maps")
			}

			if force && cleaned == 0 {
				// The datapath ran out of room and expiry alone freed nothing:
				// every entry is still inside its timeout, so the maps are at
				// capacity. Keep failing closed, but say so once a minute
				// instead of once per pressure event.
				nowNano := now.UnixNano()
				if last := j.pressureWarnAt.Load(); nowNano-last > int64(time.Minute) &&
					j.pressureWarnAt.CompareAndSwap(last, nowNano) {
					log.WithField("forced", janitorPressureNames(pressure)).
						Warnln("datapath map pressure: cleanup freed no entries, " +
							"the maps are at capacity and writes keep failing until flows expire")
				}
			}

			// Calm-state backoff: when nothing was expired, double
			// the poll interval up to janitorMaxInterval. As soon
			// as any entry was cleaned, reset to the base cadence.
			if cleaned > 0 {
				interval = janitorTickInterval
			} else {
				interval = min(interval*2, janitorMaxInterval)
			}
			if j.pressure.Load() != 0 {
				// An urgent sweep is still pending for a later window: come
				// back as soon as it may run instead of backing off.
				interval = janitorPressureSweepInterval
			}
			ticker.Reset(interval)
		}
	}()
}

func (j *bpfMapJanitor) Stop() {
	close(j.wake)
	timer := time.NewTimer(5 * time.Second)
	defer timer.Stop()
	select {
	case <-j.done:
	case <-timer.C:
		log.Warn("bpfMapJanitor.Stop: timeout waiting for janitor to exit")
	}
}

func monotonicNowNano() int64 {
	var ts unix.Timespec
	if err := unix.ClockGettime(unix.CLOCK_MONOTONIC, &ts); err != nil {
		return -1
	}
	return ts.Nano()
}

// ---- cookie_pid cleanup ----

func (j *bpfMapJanitor) cleanupCookiePidMap() int {
	bpf := j.bpf()
	if bpf == nil {
		return 0
	}
	m := bpf.CookiePidMap
	nowNano := monotonicNowNano()
	if nowNano < 0 {
		log.Error("cleanupCookiePidMap: failed to get monotonic time")
		return 0
	}
	timeoutNano := cookiePidMapTimeout.Nanoseconds()

	scratch := &j.cookiePidScratch
	defer recycleScratchDelete(&scratch.delete)

	var cursor ebpf.MapBatchCursor
	for {
		count, err := m.BatchLookup(&cursor, scratch.keys[:], scratch.values[:], nil)
		if count > 0 {
			for i := range count {
				if nowNano-int64(scratch.values[i].LastSeenNs) > timeoutNano {
					scratch.delete = append(scratch.delete, scratch.keys[i])
				}
			}
		}
		if err != nil {
			if !isIgnorableBatchLookupErr(err) {
				log.WithError(err).Error("cleanupCookiePidMap: BatchLookup error")
			}
			break
		}
	}

	if len(scratch.delete) > 0 {
		if _, err := BpfMapBatchDelete(m, scratch.delete); err != nil &&
			log.IsLevelEnabled(log.DebugLevel) {
			log.WithError(err).Debug("cleanupCookiePidMap: batch delete error")
		}
	}
	return len(scratch.delete)
}

// ---- redirect_track cleanup ----

func (j *bpfMapJanitor) cleanupRedirectTrackMap() int {
	bpf := j.bpf()
	if bpf == nil {
		return 0
	}
	m := bpf.RedirectTrack
	nowNano := monotonicNowNano()
	if nowNano < 0 {
		log.Error("cleanupRedirectTrackMap: failed to get monotonic time")
		return 0
	}
	timeoutNano := redirectTrackTimeout.Nanoseconds()

	scratch := &j.redirectScratch
	defer recycleScratchDelete(&scratch.delete)

	var cursor ebpf.MapBatchCursor
	for {
		count, err := m.BatchLookup(&cursor, scratch.keys[:], scratch.values[:], nil)
		if count > 0 {
			for i := range count {
				if nowNano-int64(scratch.values[i].LastSeenNs) > timeoutNano {
					scratch.delete = append(scratch.delete, scratch.keys[i])
				}
			}
		}
		if err != nil {
			if !isIgnorableBatchLookupErr(err) {
				log.WithError(err).Error("cleanupRedirectTrackMap: BatchLookup error")
			}
			break
		}
	}

	if len(scratch.delete) > 0 {
		if _, err := BpfMapBatchDelete(m, scratch.delete); err != nil &&
			log.IsLevelEnabled(log.DebugLevel) {
			log.WithError(err).Debug("cleanupRedirectTrackMap: batch delete error")
		}
	}
	return len(scratch.delete)
}

// ---- routing_tuples cleanup ----

func (j *bpfMapJanitor) cleanupRoutingTuplesMap() int {
	bpf := j.bpf()
	if bpf == nil {
		return 0
	}
	m := bpf.RoutingTuplesMap
	nowNano := monotonicNowNano()
	if nowNano < 0 {
		log.Error("cleanupRoutingTuplesMap: failed to get monotonic time")
		return 0
	}
	activeTimeout := routingTuplesTimeoutActive.Nanoseconds()
	udpTimeout := routingTuplesTimeoutUdp.Nanoseconds()
	closingTimeout := routingTuplesTimeoutClosing.Nanoseconds()

	scratch := &j.routingTuplesScratch
	defer recycleScratchDelete(&scratch.delete)

	var cursor ebpf.MapBatchCursor
	total := 0
	for {
		count, err := m.BatchLookup(&cursor, scratch.keys[:], scratch.values[:], nil)
		if count > 0 {
			total += count
			for i := range count {
				val := scratch.values[i]
				key := scratch.keys[i]
				timeout := closingTimeout
				if key.L4proto == unix.IPPROTO_UDP {
					timeout = udpTimeout
				} else if key.L4proto == unix.IPPROTO_TCP && val.State == 0 {
					timeout = activeTimeout
				}
				if nowNano-int64(val.LastSeenNs) > timeout {
					scratch.delete = append(scratch.delete, key)
				}
			}
		}
		if err != nil {
			if !isIgnorableBatchLookupErr(err) {
				log.WithError(err).Error("cleanupRoutingTuplesMap: BatchLookup error")
			}
			break
		}
	}
	// The scan we just did is the cheapest occupancy sample available, so
	// publish it: it is what tells a high-water trigger how full the map is.
	if common.Metrics.RoutingTuplesEntries != nil {
		common.Metrics.RoutingTuplesEntries.With0().Set(int64(total))
	}

	if len(scratch.delete) > 0 {
		if _, err := BpfMapBatchDelete(m, scratch.delete); err != nil &&
			log.IsLevelEnabled(log.DebugLevel) {
			log.WithError(err).Debug("cleanupRoutingTuplesMap: batch delete error")
		}
	}
	return len(scratch.delete)
}

func isIgnorableBatchLookupErr(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, ebpf.ErrKeyNotExist) ||
		errors.Is(err, os.ErrClosed) ||
		errors.Is(err, unix.EBADF) {
		return true
	}
	errStr := strings.ToLower(err.Error())
	return strings.Contains(errStr, "bad file descriptor") ||
		strings.Contains(errStr, "file descriptor") ||
		strings.Contains(errStr, "closed") ||
		strings.Contains(errStr, "key does not exist")
}
