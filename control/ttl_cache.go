package control

import (
	"sync"
	"time"
)

type cacheEntry[V any] struct {
	value V
	timer *time.Timer
}

type CacheWithTTL[K comparable, V any] struct {
	mu        sync.RWMutex
	data      map[K]cacheEntry[V]
	ttl       time.Duration
	onRecycle func(key K, value V)
}

func NewCacheWithTTL[K comparable, V any](ttl time.Duration, onRecycle func(key K, value V)) *CacheWithTTL[K, V] {
	return &CacheWithTTL[K, V]{
		data:      make(map[K]cacheEntry[V]),
		ttl:       ttl,
		onRecycle: onRecycle,
	}
}

func (c *CacheWithTTL[K, V]) Get(key K) (V, bool) {
	c.mu.RLock()
	entry, ok := c.data[key]
	c.mu.RUnlock()

	if !ok {
		var zero V
		return zero, false
	}
	return entry.value, true
}

func (c *CacheWithTTL[K, V]) Save(key K, value V) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if old, ok := c.data[key]; ok {
		old.timer.Stop()
		if c.onRecycle != nil {
			c.onRecycle(key, old.value)
		}
	}

	t := time.AfterFunc(c.ttl, func() {
		c.mu.Lock()
		defer c.mu.Unlock()

		if entry, ok := c.data[key]; ok {
			delete(c.data, key)
			if c.onRecycle != nil {
				c.onRecycle(key, entry.value)
			}
		}
	})

	c.data[key] = cacheEntry[V]{
		value: value,
		timer: t,
	}
}
