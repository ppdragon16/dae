/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package dialer

import (
	"sync"
	"time"
)

type LatenciesN struct {
	n             int
	latencies     []time.Duration
	sumNLatencies time.Duration
	index         int
	count         int
	mu            sync.Mutex
}

func NewLatenciesN(n int) *LatenciesN {
	return &LatenciesN{
		n:         n,
		latencies: make([]time.Duration, n),
	}
}

// AppendLatency appends a new latency to the back and keep the number in the list. Appending a fixed duration for
// failed or timeout situation is recommended.
//
// It is thread-safe.
func (ln *LatenciesN) AppendLatency(l time.Duration) {
	ln.mu.Lock()
	defer ln.mu.Unlock()
	if ln.count == ln.n {
		ln.sumNLatencies -= ln.latencies[ln.index]
	} else {
		ln.count++
	}
	ln.latencies[ln.index] = l
	ln.sumNLatencies += l
	ln.index = (ln.index + 1) % ln.n
}

func (ln *LatenciesN) LastLatency() (time.Duration, bool) {
	ln.mu.Lock()
	defer ln.mu.Unlock()
	if ln.count == 0 {
		return 0, false
	}
	return ln.latencies[(ln.index-1+ln.n)%ln.n], true
}

func (ln *LatenciesN) AvgLatency() (time.Duration, bool) {
	ln.mu.Lock()
	defer ln.mu.Unlock()
	if ln.count == 0 {
		return 0, false
	}
	return ln.sumNLatencies / time.Duration(ln.count), true
}
