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
	// cookiePidJanitorInterval is the tick interval for scanning cookie_pid_map.
	cookiePidJanitorInterval = 30 * time.Second

	// cookiePidMapTimeout is the TTL for cookie_pid entries without a refresh.
	cookiePidMapTimeout = 5 * time.Minute

	// janitorBatchLookupSize is the number of entries read per BatchLookup call.
	janitorBatchLookupSize = 1024

	// janitorDeleteInitCap is the initial capacity for the delete scratch slice.
	janitorDeleteInitCap = 256

	// janitorDeleteRetainMax is the maximum retained capacity for the delete
	// scratch slice.
	janitorDeleteRetainMax = 8192
)

// cookiePidJanitorScratch holds reusable buffers for a single janitor tick,
// avoiding per-tick allocations for BatchLookup and BatchDelete.
type cookiePidJanitorScratch struct {
	keys   []uint64
	values []bpfPidPname
	delete []uint64
}

// bpfMapJanitor manages the background goroutine that periodically
// scans and prunes stale entries from eBPF maps that use HASH (not LRU).
//
// Currently handles cookie_pid_map only; designed to be extended with additional
// scratch slots and staggered cleanup intervals for redirect_track and
// routing_tuples_map.
type bpfMapJanitor struct {
	cookiePidMap func() *ebpf.Map

	stop    chan struct{}
	done    chan struct{}
	scratch cookiePidJanitorScratch
}

func newControlPlaneDatapathJanitor(cookiePidMap func() *ebpf.Map) bpfMapJanitor {
	return bpfMapJanitor{
		cookiePidMap: cookiePidMap,
		stop:         make(chan struct{}),
		done:         make(chan struct{}),
	}
}

func (j *bpfMapJanitor) Start(ctx context.Context) {
	go func() {
		ticker := time.NewTicker(cookiePidJanitorInterval)
		defer ticker.Stop()
		defer close(j.done)

		for {
			select {
			case <-j.stop:
				return
			case <-ctx.Done():
				return
			case <-ticker.C:
				j.cleanupCookiePidMap()
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

func (j *bpfMapJanitor) cleanupCookiePidMap() int {
	m := j.cookiePidMap()
	if m == nil {
		return 0
	}

	var ts unix.Timespec
	if err := unix.ClockGettime(unix.CLOCK_MONOTONIC, &ts); err != nil {
		log.WithError(err).Error("cleanupCookiePidMap: failed to get monotonic time")
		return 0
	}
	nowNano := ts.Nano()
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

func (j *bpfMapJanitor) obtainCookiePidScratch() *cookiePidJanitorScratch {
	s := &j.scratch
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
