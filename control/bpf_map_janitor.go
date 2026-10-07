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
	routingTuplesTimeoutActive   = 30 * time.Minute
	routingTuplesTimeoutClosing  = 10 * time.Second
	routingTuplesTimeoutUdp      = 1 * time.Minute

	janitorBatchLookupSize = 64
	janitorDeleteInitCap   = 32
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
	// pressure is set by WakePressure when the datapath reports that a bounded
	// map rejected a write. The next round then ignores the per-category
	// intervals: the periodic cadence can be minutes away, while the map needs
	// room right now.
	pressure atomic.Bool
	// pressureWarnAt rate-limits the "pressure but nothing to free" warning.
	pressureWarnAt       atomic.Int64
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

// WakePressure asks for an immediate cleanup round that also ignores the
// per-category intervals. It is how a datapath write failure (reported over the
// event ring buffer) turns into an urgent sweep instead of a wait of up to
// janitorMaxInterval.
func (j *bpfMapJanitor) WakePressure() {
	j.pressure.Store(true)
	j.Wake()
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
			// A pressure round sweeps every category now, whatever the
			// per-category intervals say.
			force := j.pressure.Swap(false)

			if force || lastCookiePidCleanup.IsZero() || now.Sub(lastCookiePidCleanup) >= cookiePidJanitorInterval {
				n := j.cleanupCookiePidMap()
				cleaned += n
				lastCookiePidCleanup = now
			}
			if force || lastRedirectCleanup.IsZero() || now.Sub(lastRedirectCleanup) >= redirectTrackJanitorInterval {
				n := j.cleanupRedirectTrackMap()
				cleaned += n
				lastRedirectCleanup = now
			}
			if force || lastRoutingTuplesCleanup.IsZero() || now.Sub(lastRoutingTuplesCleanup) >= routingTuplesJanitorInterval {
				n := j.cleanupRoutingTuplesMap()
				cleaned += n
				lastRoutingTuplesCleanup = now
			}

			if force && cleaned == 0 {
				// The datapath ran out of room and expiry alone freed nothing:
				// every entry is still inside its timeout, so the maps are at
				// capacity. Keep failing closed, but say so once a minute
				// instead of once per pressure event.
				nowNano := now.UnixNano()
				if last := j.pressureWarnAt.Load(); nowNano-last > int64(time.Minute) &&
					j.pressureWarnAt.CompareAndSwap(last, nowNano) {
					log.Warnln("datapath map pressure: cleanup freed no entries, " +
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
		if _, err := BpfMapBatchDelete(m, scratch.delete); err != nil {
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
		if _, err := BpfMapBatchDelete(m, scratch.delete); err != nil {
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
		if _, err := BpfMapBatchDelete(m, scratch.delete); err != nil {
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
