package common

import (
	"context"
	"sync"
	"time"
)

const (
	minSlotSize = 64
	maxSlotSize = 1024
)

type twcEntry[K comparable, V any] struct {
	key        K
	value      V
	roundCount uint32
	slotIndex  uint32
	prev, next *twcEntry[K, V]
}

type TimeWheelCache[K comparable, V any] struct {
	mu        sync.RWMutex
	data      map[K]*twcEntry[K, V]
	onRecycle func(key K, value V, replaced bool)

	// 时间轮配置
	slots    []*twcEntry[K, V]
	slotMask uint32 // 用于位运算代替取模: index & slotMask
	slotSize uint32
	cursor   uint32
	tick     time.Duration
	ttl      time.Duration

	ctx    context.Context
	cancel context.CancelFunc
	pool   *sync.Pool
}

func NewTimeWheelCache[K comparable, V any](
	ttl time.Duration, tick time.Duration, onRecycle func(key K, value V, replaced bool)) *TimeWheelCache[K, V] {
	size := uint32(ttl / tick)
	if size > maxSlotSize {
		size = maxSlotSize
	} else if size < minSlotSize {
		size = minSlotSize
	} else {
		// 向上取 2 的幂运算
		size--
		size |= size >> 1
		size |= size >> 2
		size |= size >> 4
		size |= size >> 8
		size |= size >> 16
		size++
		if size > maxSlotSize {
			size = maxSlotSize
		}
	}

	ctx, cancel := context.WithCancel(context.Background())
	c := &TimeWheelCache[K, V]{
		data:      make(map[K]*twcEntry[K, V], size*2), // pre-alloc
		slots:     make([]*twcEntry[K, V], size),
		slotSize:  size,
		slotMask:  size - 1, // 预计算掩码
		tick:      tick,
		ttl:       ttl,
		onRecycle: onRecycle,
		ctx:       ctx,
		cancel:    cancel,
		pool: &sync.Pool{
			New: func() any { return &twcEntry[K, V]{} },
		},
	}
	go c.wheelLoop()
	return c
}

func (c *TimeWheelCache[K, V]) wheelLoop() {
	ticker := time.NewTicker(c.tick)
	defer ticker.Stop()

	for {
		select {
		case <-c.ctx.Done():
			return
		case <-ticker.C:
			c.mu.Lock()
			// 使用位运算推进指针
			c.cursor = (c.cursor + 1) & c.slotMask
			c.evictSlot(c.cursor)
			c.mu.Unlock()
		}
	}
}

func (c *TimeWheelCache[K, V]) evictSlot(index uint32) {
	curr := c.slots[index]
	for curr != nil {
		next := curr.next
		if curr.roundCount <= 0 {
			c.removeEntry(curr)
			if c.onRecycle != nil {
				c.onRecycle(curr.key, curr.value, false)
			}
			c.releaseEntry(curr)
		} else {
			curr.roundCount--
		}
		curr = next
	}
}

func (c *TimeWheelCache[K, V]) Save(key K, value V) {
	c.SaveWithTTL(key, value, c.ttl)
}

func (c *TimeWheelCache[K, V]) SaveWithTTL(key K, value V, ttl time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if old, ok := c.data[key]; ok {
		c.removeEntry(old)
		if c.onRecycle != nil {
			c.onRecycle(key, old.value, true)
		}
		c.releaseEntry(old)
	}

	entry := c.pool.Get().(*twcEntry[K, V])
	entry.key = key
	entry.value = value

	if ttl < c.tick {
		ttl = c.tick
	}
	totalTicks := uint32(ttl / c.tick)
	entry.roundCount = totalTicks / c.slotSize
	// 使用位运算定位槽位
	entry.slotIndex = (c.cursor + totalTicks) & c.slotMask

	// 插入链表头部
	entry.next = c.slots[entry.slotIndex]
	entry.prev = nil
	if entry.next != nil {
		entry.next.prev = entry
	}
	c.slots[entry.slotIndex] = entry

	c.data[key] = entry
}

func (c *TimeWheelCache[K, V]) Get(key K) (V, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if entry, ok := c.data[key]; ok {
		return entry.value, true
	}
	var zero V
	return zero, false
}

func (c *TimeWheelCache[K, V]) GetWithKey(key K) (V, K, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if entry, ok := c.data[key]; ok {
		return entry.value, entry.key, true
	}
	var zeroV V
	return zeroV, key, false
}

// Range calls fn for each (key, value, ttl) currently in the cache.
// ttl is the remaining time until the entry expires from the time wheel.
// Iteration order is unspecified. The cache's read lock is held for the
// duration of iteration; fn must not call Save/SaveWithTTL on the same
// cache (would deadlock). Returning false stops iteration early.
// Safe for concurrent Get callers.
func (c *TimeWheelCache[K, V]) Range(fn func(key K, value V, ttl time.Duration) bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	for k, e := range c.data {
		remainingTicks := uint64(e.roundCount)*uint64(c.slotSize) + uint64((e.slotIndex-c.cursor)&c.slotMask)
		remaining := time.Duration(remainingTicks) * c.tick
		if !fn(k, e.value, remaining) {
			return
		}
	}
}

func (c *TimeWheelCache[K, V]) removeEntry(entry *twcEntry[K, V]) {
	delete(c.data, entry.key)
	if entry.prev != nil {
		entry.prev.next = entry.next
	} else {
		c.slots[entry.slotIndex] = entry.next
	}
	if entry.next != nil {
		entry.next.prev = entry.prev
	}
}

func (c *TimeWheelCache[K, V]) releaseEntry(entry *twcEntry[K, V]) {
	var zeroK K
	var zeroV V
	entry.key = zeroK
	entry.value = zeroV
	entry.prev = nil
	entry.next = nil
	entry.roundCount = 0
	entry.slotIndex = 0
	c.pool.Put(entry)
}

func (c *TimeWheelCache[K, V]) Close() error {
	c.cancel()
	return nil
}
