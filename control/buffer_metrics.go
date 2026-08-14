/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"strconv"
	"time"

	"github.com/daeuniverse/dae/common"
	"github.com/daeuniverse/outbound/pool"
)

// bufferPoolMetricsInterval is how often the buffer pool stats are sampled into
// the registry. The gauges hold the latest cumulative counters, so this interval
// only bounds staleness; Prometheus derives rates over its own scrape window.
const bufferPoolMetricsInterval = 10 * time.Second

// startBufferPoolMetrics publishes the per-class buffer pool counters and ring
// occupancy to the metrics registry. Reuse efficiency is derived in Prometheus,
// e.g. hit rate = 1 - rate(dae_buffer_pool_allocs)/rate(dae_buffer_pool_gets).
func startBufferPoolMetrics() {
	go func() {
		var stats pool.StatsSnapshot
		// Class-size labels never change, so build them once instead of
		// allocating a fresh string per class on every sample.
		labels := make([]string, len(stats))
		for i := range labels {
			labels[i] = strconv.Itoa(1 << i)
		}
		t := time.NewTicker(bufferPoolMetricsInterval)
		defer t.Stop()
		for range t.C {
			pool.PoolStats(&stats)
			for i, s := range stats {
				common.Metrics.BufferPoolGets.With1(labels[i]).Set(int64(s.Gets))
				common.Metrics.BufferPoolRingHits.With1(labels[i]).Set(int64(s.RingHit))
				common.Metrics.BufferPoolPoolHits.With1(labels[i]).Set(int64(s.PoolHit))
				common.Metrics.BufferPoolAllocs.With1(labels[i]).Set(int64(s.Alloc))
				common.Metrics.BufferPoolDemoted.With1(labels[i]).Set(int64(s.Demoted))
				common.Metrics.BufferPoolOccupancy.With1(labels[i]).Set(int64(s.Occupancy))
				common.Metrics.BufferPoolMax.With1(labels[i]).Set(int64(s.Max))
			}
		}
	}()
}
