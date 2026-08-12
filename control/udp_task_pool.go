/*
*  SPDX-License-Identifier: AGPL-3.0-only
*  Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"sync"
	"sync/atomic"
	"time"
)

// UdpTaskPool executes tasks keyed by UDP flow, one convoy goroutine per key.
// Tasks sharing a key are drained from a bounded channel in FIFO order, so
// they reach handlePkt in the same order EmitTask enqueued them.
//
// Note this only preserves order from EmitTask onward. The enqueue order is
// whatever order callers invoke EmitTask in, so to keep same-flow packets in
// wire (arrival) order, EmitTask MUST be called from the single serial read
// loop (loopUdp). Calling it from concurrent workers would reorder packets
// before they ever reach the queue, defeating the purpose — which is why the
// ordering-sensitive path emits directly from loopUdp rather than through the
// udpWorker pool.
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

// EmitTask enqueues a task for key. Tasks sharing a key run in FIFO enqueue
// order via a single convoy goroutine; see the UdpTaskPool doc comment for the
// ordering guarantee's precondition (call from the serial read loop).
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

func AddrPortPairHash(k AddrPortPair) uint32 {
	// Reuse the sharded hash with a full mask to obtain the unmasked 32-bit
	// hash of the {src,dst} pair.
	return AddrPortPairShard(k, ^uint32(0))
}
