package common

import (
	"sync"

	"github.com/prometheus/client_golang/prometheus"
)

var (
	ActiveConnections  *prometheus.GaugeVec
	CoreIpDomainBitmap prometheus.Gauge
	DeadlineTimers     prometheus.Gauge
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
	DeadlineTimers = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Name: "dae_deadline_timers",
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
	registry.MustRegister(DeadlineTimers)
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

var labelsPool = sync.Pool{New: func() any { return prometheus.Labels{"outbound": "", "subtag": "", "dialer": "", "network": ""} }}

func ObtainPrometheusLabels(outbound string, subtag string, dialer string, network string) prometheus.Labels {
	v := labelsPool.Get()
	labels := v.(prometheus.Labels)
	labels["outbound"] = outbound
	labels["subtag"] = subtag
	labels["dialer"] = dialer
	labels["network"] = network
	return labels
}

func RecyclePrometheusLabels(labels prometheus.Labels) {
	labelsPool.Put(labels)
}
