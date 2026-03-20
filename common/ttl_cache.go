package common

import (
	"container/list"
	"context"
	"sync"
	"time"
)

const (
	CleanupTickMin = 5 * time.Second
	CleanupTickMax = 10 * time.Minute
)

type cacheEntry[K any, V any] struct {
	key      K
	value    V
	expireAt time.Time
	element  *list.Element
}

type listEntry[K any] struct {
	key      K
	expireAt time.Time
}

type CacheWithTTL[K comparable, V any] struct {
	mu         sync.RWMutex
	data       map[K]cacheEntry[K, V]
	expireList *list.List
	ttl        time.Duration
	onRecycle  func(key K, value V)
	ctx        context.Context
	cancel     context.CancelFunc
}

func NewCacheWithTTL[K comparable, V any](ttl time.Duration, onRecycle func(key K, value V)) *CacheWithTTL[K, V] {
	ctx, cancel := context.WithCancel(context.Background())
	c := &CacheWithTTL[K, V]{
		data:       make(map[K]cacheEntry[K, V]),
		expireList: list.New(),
		ttl:        ttl,
		onRecycle:  onRecycle,
		ctx:        ctx,
		cancel:     cancel,
	}
	go c.cleanupLoop()
	return c
}

func (c *CacheWithTTL[K, V]) cleanupLoop() {
	interval := min(max(c.ttl/10, CleanupTickMin), CleanupTickMax)
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-c.ctx.Done():
			return
		case <-ticker.C:
		}
		now := time.Now()
		c.mu.Lock()
		for {
			element := c.expireList.Front()
			if element == nil {
				break
			}

			entry := element.Value.(listEntry[K])
			if now.Before(entry.expireAt) {
				break
			}

			c.expireList.Remove(element)

			if c.onRecycle != nil {
				value := c.data[entry.key].value
				delete(c.data, entry.key)
				c.onRecycle(entry.key, value)
			} else {
				delete(c.data, entry.key)
			}
		}
		c.mu.Unlock()
	}
}

func (c *CacheWithTTL[K, V]) Close() error {
	c.cancel()
	return nil
}

func (c *CacheWithTTL[K, V]) Get(key K) (V, bool) {
	c.mu.RLock()
	entry, ok := c.data[key]
	c.mu.RUnlock()

	if ok && time.Now().Before(entry.expireAt) {
		return entry.value, true
	}
	var zero V
	return zero, false
}

func (c *CacheWithTTL[K, V]) GetWithKey(key K) (V, K, bool) {
	c.mu.RLock()
	entry, ok := c.data[key]
	c.mu.RUnlock()

	if ok && time.Now().Before(entry.expireAt) {
		return entry.value, entry.key, true
	}
	var zeroV V
	return zeroV, key, false
}

func (c *CacheWithTTL[K, V]) Save(key K, value V) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if old, ok := c.data[key]; ok {
		c.expireList.Remove(old.element)
		if c.onRecycle != nil {
			c.onRecycle(key, old.value)
		}
	}

	expireAt := time.Now().Add(c.ttl)
	c.data[key] = cacheEntry[K, V]{
		key:      key,
		value:    value,
		expireAt: expireAt,
		element: c.expireList.PushBack(listEntry[K]{
			key:      key,
			expireAt: expireAt,
		}),
	}
}
