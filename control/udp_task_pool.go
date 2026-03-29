/*
*  SPDX-License-Identifier: AGPL-3.0-only
*  Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"context"
	"net/netip"
	"sync"
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
	key K
	p   *UdpTaskPool[K, P]

	// mu protects valid and ch usage between EmitTask and GC
	mu    sync.RWMutex
	valid bool

	ch        chan *UdpTask[P]
	timer     *time.Timer
	agingTime time.Duration
	ctx       context.Context
	cancel    context.CancelFunc
	closed    chan struct{}
}

func (q *UdpTaskQueue[K, P]) convoy() {
	defer close(q.closed)
	for {
		select {
		case <-q.ctx.Done():
			return
		case task := <-q.ch:
			task.exec(task)
			// Reset timer safely
			if !q.timer.Stop() {
				select {
				case <-q.timer.C:
				default:
				}
			}
			q.timer.Reset(q.agingTime)
		}
	}
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
				ch:     make(chan *UdpTask[P], UdpTaskQueueLength),
				closed: make(chan struct{}),
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
		q.mu.RLock()
		if q.valid {
			select {
			case q.ch <- task:
				q.mu.RUnlock()
				shard.mu.RUnlock()
				return true
			default:
				// Channel full
			}
		}
		q.mu.RUnlock()
	}
	shard.mu.RUnlock()

	// Slow path or retry
	shard.mu.Lock()
	// Double check
	q, ok = shard.m[key]
	if ok {
		// Someone created it just now
		q.mu.RLock()
		if q.valid {
			select {
			case q.ch <- task:
				q.mu.RUnlock()
				shard.mu.Unlock()
				return true
			default:
			}
		}
		q.mu.RUnlock()
	} else {
		// Create new
		q = p.queuePool.Get().(*UdpTaskQueue[K, P])
		q.key = key
		q.p = p
		q.valid = true
		q.agingTime = DefaultNatTimeoutUDP
		// Reset closed channel if it was closed
		select {
		case <-q.closed:
			q.closed = make(chan struct{})
		default:
		}

		q.ctx, q.cancel = context.WithCancel(context.Background())

		q.timer = time.AfterFunc(q.agingTime, func() {
			shard.mu.Lock()
			if shard.m[key] != q {
				shard.mu.Unlock()
				return
			}
			delete(shard.m, key)
			shard.mu.Unlock()

			// Mark invalid
			q.mu.Lock()
			q.valid = false
			q.mu.Unlock()

			q.cancel()
			<-q.closed

			// Drain channel before recycling
			for len(q.ch) > 0 {
				<-q.ch
			}
			p.queuePool.Put(q)
		})
		shard.m[key] = q
		go q.convoy()

		// Send task to newly created queue (guaranteed to have space)
		q.ch <- task
		shard.mu.Unlock()
		return true
	}
	shard.mu.Unlock()
	return false
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
