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
	"time"

	"github.com/cilium/ebpf"
	log "github.com/sirupsen/logrus"
	"golang.org/x/sys/unix"
)

const (
	// Base tick interval for the janitor goroutine.
	janitorTickInterval = 10 * time.Second

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
	routingTuplesTimeoutUdp      = 5 * time.Minute

	janitorBatchLookupSize = 1024
	janitorDeleteInitCap   = 256
	janitorDeleteRetainMax = 8192
)

// ---- cookie_pid scratch ----

type cookiePidJanitorScratch struct {
	keys   []uint64
	values []bpfPidPname
	delete []uint64
}

func (j *bpfMapJanitor) obtainCookiePidScratch() *cookiePidJanitorScratch {
	s := &j.cookiePidScratch
	if cap(s.keys) < janitorBatchLookupSize {
		s.keys = make([]uint64, janitorBatchLookupSize)
	}
	if cap(s.values) < janitorBatchLookupSize {
		s.values = make([]bpfPidPname, janitorBatchLookupSize)
	}
	if cap(s.delete) < janitorDeleteInitCap {
		s.delete = make([]uint64, 0, janitorDeleteInitCap)
	} else {
		s.delete = s.delete[:0]
	}
	return s
}

func recycleCookiePidScratch(s *cookiePidJanitorScratch) {
	if cap(s.delete) > janitorDeleteRetainMax {
		s.delete = make([]uint64, 0, janitorDeleteInitCap)
	} else {
		s.delete = s.delete[:0]
	}
}

// ---- redirect_track scratch ----

type redirectTrackJanitorScratch struct {
	keys   []bpfRedirectTuple
	values []bpfRedirectEntry
	delete []bpfRedirectTuple
}

func (j *bpfMapJanitor) obtainRedirectTrackScratch() *redirectTrackJanitorScratch {
	s := &j.redirectScratch
	if cap(s.keys) < janitorBatchLookupSize {
		s.keys = make([]bpfRedirectTuple, janitorBatchLookupSize)
	}
	if cap(s.values) < janitorBatchLookupSize {
		s.values = make([]bpfRedirectEntry, janitorBatchLookupSize)
	}
	if cap(s.delete) < janitorDeleteInitCap {
		s.delete = make([]bpfRedirectTuple, 0, janitorDeleteInitCap)
	} else {
		s.delete = s.delete[:0]
	}
	return s
}

func recycleRedirectTrackScratch(s *redirectTrackJanitorScratch) {
	if cap(s.delete) > janitorDeleteRetainMax {
		s.delete = make([]bpfRedirectTuple, 0, janitorDeleteInitCap)
	} else {
		s.delete = s.delete[:0]
	}
}

// ---- routing_tuples scratch ----

type routingTuplesJanitorScratch struct {
	keys   []bpfTuplesKey
	values []bpfRoutingResult
	delete []bpfTuplesKey
}

func (j *bpfMapJanitor) obtainRoutingTuplesScratch() *routingTuplesJanitorScratch {
	s := &j.routingTuplesScratch
	if cap(s.keys) < janitorBatchLookupSize {
		s.keys = make([]bpfTuplesKey, janitorBatchLookupSize)
	}
	if cap(s.values) < janitorBatchLookupSize {
		s.values = make([]bpfRoutingResult, janitorBatchLookupSize)
	}
	if cap(s.delete) < janitorDeleteInitCap {
		s.delete = make([]bpfTuplesKey, 0, janitorDeleteInitCap)
	} else {
		s.delete = s.delete[:0]
	}
	return s
}

func recycleRoutingTuplesScratch(s *routingTuplesJanitorScratch) {
	if cap(s.delete) > janitorDeleteRetainMax {
		s.delete = make([]bpfTuplesKey, 0, janitorDeleteInitCap)
	} else {
		s.delete = s.delete[:0]
	}
}

// ---- janitor ----

type bpfMapJanitor struct {
	bpf func() *bpfObjects

	stop                 chan struct{}
	done                 chan struct{}
	cookiePidScratch     cookiePidJanitorScratch
	redirectScratch      redirectTrackJanitorScratch
	routingTuplesScratch routingTuplesJanitorScratch
}

func newBpfMapJanitor(bpf func() *bpfObjects) bpfMapJanitor {
	return bpfMapJanitor{
		bpf:  bpf,
		stop: make(chan struct{}),
		done: make(chan struct{}),
	}
}

func (j *bpfMapJanitor) Start(ctx context.Context) {
	go func() {
		ticker := time.NewTicker(janitorTickInterval)
		defer ticker.Stop()
		defer close(j.done)

		var lastCookiePidCleanup, lastRedirectCleanup, lastRoutingTuplesCleanup time.Time

		for {
			select {
			case <-j.stop:
				return
			case <-ctx.Done():
				return
			case now := <-ticker.C:
				if lastCookiePidCleanup.IsZero() || now.Sub(lastCookiePidCleanup) >= cookiePidJanitorInterval {
					j.cleanupCookiePidMap()
					lastCookiePidCleanup = now
				}
				if lastRedirectCleanup.IsZero() || now.Sub(lastRedirectCleanup) >= redirectTrackJanitorInterval {
					j.cleanupRedirectTrackMap()
					lastRedirectCleanup = now
				}
				if lastRoutingTuplesCleanup.IsZero() || now.Sub(lastRoutingTuplesCleanup) >= routingTuplesJanitorInterval {
					j.cleanupRoutingTuplesMap()
					lastRoutingTuplesCleanup = now
				}
			}
		}
	}()
}

func (j *bpfMapJanitor) Stop() {
	close(j.stop)
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

	scratch := j.obtainCookiePidScratch()
	defer recycleCookiePidScratch(scratch)

	var cursor ebpf.MapBatchCursor
	for {
		count, err := m.BatchLookup(&cursor, scratch.keys, scratch.values, nil)
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

	scratch := j.obtainRedirectTrackScratch()
	defer recycleRedirectTrackScratch(scratch)

	var cursor ebpf.MapBatchCursor
	for {
		count, err := m.BatchLookup(&cursor, scratch.keys, scratch.values, nil)
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

	scratch := j.obtainRoutingTuplesScratch()
	defer recycleRoutingTuplesScratch(scratch)

	var cursor ebpf.MapBatchCursor
	for {
		count, err := m.BatchLookup(&cursor, scratch.keys, scratch.values, nil)
		if count > 0 {
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
