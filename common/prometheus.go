package common

import (
	"sync"

	"github.com/prometheus/client_golang/prometheus"
)

// labelsCache 按 (outbound, subtag, dialer, network) 组合缓存 Labels 实例。
// 组合数量有限（~200），预分配后 Get 仅为 map lookup，无锁竞争。
var labelsCache atomicLabelsCache

type atomicLabelsCache struct {
	sync.RWMutex
	m map[uint64]prometheus.Labels
}

func fnv64(s string) uint64 {
	h := uint64(14695981039346656037) // FNV offset basis
	for i := 0; i < len(s); i++ {
		h ^= uint64(s[i])
		h *= 1099511628211 // FNV prime
	}
	return h
}

func (c *atomicLabelsCache) Get(outbound, subtag, dialer, network string) prometheus.Labels {
	key := fnv64(outbound)
	key = key*1099511628211 ^ fnv64(subtag)
	key = key*1099511628211 ^ fnv64(dialer)
	key = key*1099511628211 ^ fnv64(network)

	c.RLock()
	labels, ok := c.m[key]
	c.RUnlock()
	if ok {
		return labels
	}
	c.Lock()
	defer c.Unlock()
	if c.m == nil {
		c.m = make(map[uint64]prometheus.Labels)
	}
	if labels, ok = c.m[key]; !ok {
		labels = prometheus.Labels{
			"outbound": outbound,
			"subtag":   subtag,
			"dialer":   dialer,
			"network":  network,
		}
		c.m[key] = labels
	}
	return labels
}

func GetPrometheusLabels(outbound, subtag, dialer, network string) prometheus.Labels {
	return labelsCache.Get(outbound, subtag, dialer, network)
}

var (
	ActiveConnections  *prometheus.GaugeVec
	CoreIpDomainBitmap prometheus.Gauge
	DnsCacheSize       prometheus.Gauge
	CheckLatency       *prometheus.GaugeVec
	CheckMovingLatency *prometheus.GaugeVec
	CheckSelectLatency *prometheus.GaugeVec
	DialerSelectIndex  *prometheus.GaugeVec
	ErrorCount         *prometheus.CounterVec
	TrafficBytes       *prometheus.CounterVec
	StackInuse         prometheus.Gauge
	HeapInuse          prometheus.Gauge
	HeapIdle           prometheus.Gauge
	HeapReleased       prometheus.Gauge
)

func InitPrometheus(registry *prometheus.Registry) {
	labels := []string{"outbound", "subtag", "dialer", "network"}
	ActiveConnections = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "dae_active_connections",
		},
		labels,
	)
	CoreIpDomainBitmap = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Name: "dae_ip_domain_bitmap",
		},
	)
	DnsCacheSize = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Name: "dae_dns_cache_size",
		},
	)
	CheckLatency = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "dae_check_latency",
		},
		labels,
	)
	CheckMovingLatency = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "dae_check_moving_latency",
		},
		labels,
	)
	CheckSelectLatency = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "dae_check_select_latency",
		},
		labels,
	)
	DialerSelectIndex = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "dae_dialer_select_index",
		},
		labels,
	)
	ErrorCount = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "dae_error_count",
		},
		labels,
	)
	TrafficBytes = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "dae_traffic_bytes",
		},
		labels,
	)
	StackInuse = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Name: "dae_stack_inuse_kb",
		},
	)
	HeapInuse = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Name: "dae_heap_inuse_kb",
		},
	)
	HeapIdle = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Name: "dae_heap_idle_kb",
		},
	)
	HeapReleased = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Name: "dae_heap_released_kb",
		},
	)
	registry.MustRegister(ActiveConnections)
	registry.MustRegister(CoreIpDomainBitmap)
	registry.MustRegister(DnsCacheSize)
	registry.MustRegister(CheckLatency)
	registry.MustRegister(CheckMovingLatency)
	registry.MustRegister(CheckSelectLatency)
	registry.MustRegister(DialerSelectIndex)
	registry.MustRegister(ErrorCount)
	registry.MustRegister(TrafficBytes)
	registry.MustRegister(StackInuse)
	registry.MustRegister(HeapInuse)
	registry.MustRegister(HeapIdle)
	registry.MustRegister(HeapReleased)
}
