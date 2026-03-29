/*
*  SPDX-License-Identifier: AGPL-3.0-only
*  Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"net/netip"
	"sync"
	"sync/atomic"
	"time"
)

const UdpTaskQueueLength = 128
const shardingCount = 128

type Hasher[K comparable] func(K) uint32

type UdpTask[ParamType any] struct {
	param ParamType
	exec  func(*UdpTask[ParamType])
}

type UdpTaskQueue[K comparable, P any] struct {
	key   K
	valid int32

	ch        chan *UdpTask[P]
	agingTime time.Duration
}

func convoy[K comparable, P any](q *UdpTaskQueue[K, P], p *UdpTaskPool[K, P]) {
	t := time.NewTimer(q.agingTime)
	defer t.Stop()

	for {
		select {
		case task := <-q.ch:
			task.exec(task)
			if !t.Stop() {
				select {
				case <-t.C:
				default:
				}
			}
			t.Reset(q.agingTime)

		case <-t.C:
			cleanup(q, p)
			return
		}
	}
}

func cleanup[K comparable, P any](q *UdpTaskQueue[K, P], p *UdpTaskPool[K, P]) {
	h := p.hasher(q.key)
	shard := p.shards[h%uint32(shardingCount)]

	shard.mu.Lock()
	atomic.StoreInt32(&q.valid, 0)

	if shard.m[q.key] == q {
		delete(shard.m, q.key)
	}
	shard.mu.Unlock()

	for {
		select {
		case t := <-q.ch:
			// Ensures task recycled
			t.exec(t)
		default:
			goto done
		}
	}
done:
	q.key = *new(K)
	p.queuePool.Put(q)
}

type udpTaskPoolShard[K comparable, P any] struct {
	mu sync.RWMutex
	m  map[K]*UdpTaskQueue[K, P]
}

type UdpTaskPool[K comparable, P any] struct {
	queuePool sync.Pool
	shards    [shardingCount]*udpTaskPoolShard[K, P]
	hasher    Hasher[K]
}

func NewUdpTaskPool[K comparable, P any](hasher Hasher[K]) *UdpTaskPool[K, P] {
	p := &UdpTaskPool[K, P]{
		queuePool: sync.Pool{New: func() any {
			return &UdpTaskQueue[K, P]{
				ch: make(chan *UdpTask[P], UdpTaskQueueLength),
			}
		}},
		hasher: hasher,
	}
	for i := 0; i < shardingCount; i++ {
		p.shards[i] = &udpTaskPoolShard[K, P]{
			m: make(map[K]*UdpTaskQueue[K, P]),
		}
	}
	return p
}

// EmitTask: Make sure packets with the same key (4 tuples) will be sent in order.
func (p *UdpTaskPool[K, P]) EmitTask(key K, task *UdpTask[P]) bool {
	h := p.hasher(key)
	shard := p.shards[h%uint32(shardingCount)]
	shard.mu.RLock()
	q, ok := shard.m[key]
	if ok {
		// Fast path: try to lock queue safely
		if atomic.LoadInt32(&q.valid) == 1 {
			select {
			case q.ch <- task:
				shard.mu.RUnlock()
				return true
			default:
				// Channel full
			}
		}
	}
	shard.mu.RUnlock()

	// Slow path or retry
	shard.mu.Lock()
	defer shard.mu.Unlock()

	// Double check
	q, ok = shard.m[key]
	if ok {
		// Someone created it just now
		if atomic.LoadInt32(&q.valid) == 1 {
			select {
			case q.ch <- task:
				return true
			default:
			}
		}
		return false
	}
	// Create new
	q = p.queuePool.Get().(*UdpTaskQueue[K, P])
	q.key = key
	atomic.StoreInt32(&q.valid, 1)
	q.agingTime = DefaultNatTimeoutUDP

	shard.m[key] = q
	go convoy(q, p)

	// Send task to newly created queue (guaranteed to have space)
	q.ch <- task
	return true
}

func AddrPortHash(k netip.AddrPort) uint32 {
	addr := k.Addr()
	// FNV-1a like hash for 16 bytes addr + 2 bytes port
	// We can't access internal fields efficiently without allocation if we use Interface()
	// But AddrPort is comparable.
	// As16() returns [16]byte array
	b16 := addr.As16()
	var h uint32 = 2166136261
	for _, b := range b16 {
		h ^= uint32(b)
		h *= 16777619
	}
	port := k.Port()
	h ^= uint32(port >> 8)
	h *= 16777619
	h ^= uint32(port & 0xFF)
	h *= 16777619
	return h
}
