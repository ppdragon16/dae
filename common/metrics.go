package common

import (
	"hash/maphash"
	"io"
	"net/http"
	"strconv"
	"sync"
	"sync/atomic"
)

var (
	// globalRegistry 存储所有已创建的指标
	globalRegistry []*Gauge
	registryMu     sync.RWMutex

	// 预分配一个小的栈缓冲区池，供 Gather 使用
	// 这样即便并发抓取，也不产生堆分配
	lineBufPool = sync.Pool{
		New: func() any {
			b := make([]byte, 1024) // 1KB 足够格式化单行指标
			return &b
		},
	}
)

// Series 存储预格式化的标签前缀和原子数值
type Series struct {
	prefix []byte       // 预生成的 "metric_name{label1="v1",...} "
	value  atomic.Int64 // 原子操作，确保高频更新无锁
}

// Gauge 核心结构
type Gauge struct {
	name      string
	labelKeys []string
	// 使用 sync.Map 保证 With 查找在高并发下依然高效且线程安全
	series sync.Map // map[string]*Series
}

var metricSeed = maphash.MakeSeed()

// NewGauge 构造函数：预锁定定制标签键名
func NewGauge(name string, labelKeys ...string) *Gauge {
	registryMu.Lock()
	defer registryMu.Unlock()

	for _, existing := range globalRegistry {
		if existing.name == name {
			return existing
		}
	}

	g := &Gauge{
		name:      name,
		labelKeys: labelKeys,
	}
	globalRegistry = append(globalRegistry, g)
	return g
}

// --- 强类型 With 接口：彻底规避 ...string 产生的切片逃逸 ---

func (g *Gauge) With0() *Series {
	if s, ok := g.series.Load(uint64(0)); ok {
		return s.(*Series)
	}
	return g.createSlow(0, "", "", "", "")
}

func (g *Gauge) With1(v1 string) *Series {
	var h maphash.Hash
	h.SetSeed(metricSeed)
	h.WriteString(v1)
	key := h.Sum64()

	if s, ok := g.series.Load(key); ok {
		return s.(*Series)
	}
	return g.createSlow(key, v1, "", "", "")
}

func (g *Gauge) With2(v [2]string) *Series {
	var h maphash.Hash
	h.SetSeed(metricSeed)
	h.WriteString(v[0])
	h.WriteString(v[1])
	key := h.Sum64()

	if s, ok := g.series.Load(key); ok {
		return s.(*Series)
	}
	return g.createSlow(key, v[0], v[1], "", "")
}

func (g *Gauge) With3(v [3]string) *Series {
	var h maphash.Hash
	h.Reset()
	h.SetSeed(metricSeed)
	h.WriteString(v[0])
	h.WriteString(v[1])
	h.WriteString(v[2])
	key := h.Sum64()

	if s, ok := g.series.Load(key); ok {
		return s.(*Series)
	}
	return g.createSlow(key, v[0], v[1], v[2], "")
}

func (g *Gauge) With4(v [4]string) *Series {
	var h maphash.Hash
	h.SetSeed(metricSeed)
	h.WriteString(v[0])
	h.WriteString(v[1])
	h.WriteString(v[2])
	h.WriteString(v[3])
	key := h.Sum64()

	if s, ok := g.series.Load(key); ok {
		return s.(*Series)
	}
	return g.createSlow(key, v[0], v[1], v[2], v[3])
}

// Drop 删除指定标签组合的 Series，用于清理不再需要的残余指标
func (g *Gauge) Drop(v []string) {
	var key uint64
	if len(v) > 0 {
		var h maphash.Hash
		h.SetSeed(metricSeed)
		for _, s := range v {
			h.WriteString(s)
		}
		key = h.Sum64()
	}
	g.series.Delete(key)
}

// getOrCreate 核心逻辑：显式参数传递，彻底规避切片逃逸
func (g *Gauge) createSlow(key uint64, v1, v2, v3, v4 string) *Series {
	// 2. 慢路径：创建新 Series (仅在每个标签组合第一次出现时运行)
	// 预估容量：指标名 + 4对标签键值 + 标点符号，128字节通常足够
	buf := make([]byte, 0, 128)
	buf = append(buf, g.name...)

	numKeys := len(g.labelKeys)
	if numKeys > 4 {
		numKeys = 4
	}
	if numKeys > 0 {
		buf = append(buf, '{')
		vals := [4]string{v1, v2, v3, v4}

		for i := 0; i < numKeys; i++ {
			buf = append(buf, g.labelKeys[i]...)
			buf = append(buf, '=', '"')
			buf = append(buf, vals[i]...)
			buf = append(buf, '"')
			if i < numKeys-1 {
				buf = append(buf, ',')
			}
		}
		buf = append(buf, '}')
	}

	// 标准 Prometheus 格式：指标名与数值之间必须有一个空格
	buf = append(buf, ' ')

	newS := &Series{prefix: buf}

	// 使用 LoadOrStore 确保并发环境下 Series 的唯一性
	actual, _ := g.series.LoadOrStore(key, newS)
	return actual.(*Series)
}

// --- Series 数值操作：绝对无锁 ---

func (s *Series) Set(val int64) { s.value.Store(val) }
func (s *Series) Add(val int64) { s.value.Add(val) }
func (s *Series) Inc()          { s.value.Add(1) }
func (s *Series) Dec()          { s.value.Add(-1) }

// --- 流式输出：彻底解决 Gather 时的内存积压 ---

// GatherTo 将所有 Series 的数据直接写入 io.Writer
// 你需要传入一个预分配好的 lineBuf（建议 1KB 以上）来复用内存
func (g *Gauge) GatherTo(w io.Writer, lineBuf []byte) error {
	// 写入 Metadata
	temp := lineBuf[:0]
	temp = append(temp, "# HELP "...)
	temp = append(temp, g.name...)
	temp = append(temp, "\n# TYPE "...)
	temp = append(temp, g.name...)
	temp = append(temp, " gauge\n"...)
	if _, err := w.Write(temp); err != nil {
		return err
	}

	var writeErr error
	g.series.Range(func(_, value any) bool {
		s := value.(*Series)
		// 复用传入的 lineBuf
		l := lineBuf[:0]
		l = append(l, s.prefix...)
		l = strconv.AppendInt(l, s.value.Load(), 10)
		l = append(l, '\n')

		_, writeErr = w.Write(l)
		return writeErr == nil // 写入失败时停止遍历
	})

	return writeErr
}

// GatherAll 将所有注册的指标流式写入目标 Writer
func GatherAll(w io.Writer) error {
	pBuf := lineBufPool.Get().(*[]byte)
	defer lineBufPool.Put(pBuf)
	lineBuf := *pBuf

	// 读锁保护注册表遍历
	registryMu.RLock()
	defer registryMu.RUnlock()

	for _, g := range globalRegistry {
		if err := g.GatherTo(w, lineBuf); err != nil {
			return err
		}
	}
	return nil
}

func MetricsHandler(w http.ResponseWriter, r *http.Request) {
	// 1. 设置标准 Prometheus 响应头
	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
	w.WriteHeader(http.StatusOK)

	// 2. 直接流式写入，不产生任何大块内存分配
	if err := GatherAll(w); err != nil {
		// 这里不需要返回错误给客户端，因为 Header 已经发送
		// 可以记录到 dae 的日志中
		return
	}
}

var Metrics = struct {
	ActiveConnections  *Gauge
	CoreIpDomainBitmap *Gauge
	DnsCacheSize       *Gauge
	CheckLatency       *Gauge
	CheckMovingLatency *Gauge
	CheckSelectLatency *Gauge
	DialerSelectIndex  *Gauge
	ErrorCount         *Gauge
	TrafficBytes       *Gauge
	StackInuse         *Gauge
	HeapInuse          *Gauge
	HeapIdle           *Gauge
	HeapReleased       *Gauge
}{}

func InitMetrics() {
	Metrics.ActiveConnections = NewGauge("dae_active_connections", "outbound", "subtag", "dialer", "network")
	Metrics.CoreIpDomainBitmap = NewGauge("dae_ip_domain_bitmap")
	Metrics.DnsCacheSize = NewGauge("dae_dns_cache_size")
	Metrics.CheckLatency = NewGauge("dae_check_latency", "outbound", "subtag", "dialer", "network")
	Metrics.CheckMovingLatency = NewGauge("dae_check_moving_latency", "outbound", "subtag", "dialer", "network")
	Metrics.CheckSelectLatency = NewGauge("dae_check_select_latency", "outbound", "subtag", "dialer", "network")
	Metrics.DialerSelectIndex = NewGauge("dae_dialer_select_index", "outbound", "subtag", "dialer", "network")
	Metrics.ErrorCount = NewGauge("dae_error_count", "outbound", "subtag", "dialer", "network")
	Metrics.TrafficBytes = NewGauge("dae_traffic_bytes", "outbound", "subtag", "dialer", "network")
	Metrics.StackInuse = NewGauge("dae_stack_inuse_kb")
	Metrics.HeapInuse = NewGauge("dae_heap_inuse_kb")
	Metrics.HeapIdle = NewGauge("dae_heap_idle_kb")
	Metrics.HeapReleased = NewGauge("dae_heap_released_kb")
}
