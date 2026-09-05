/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"sync"
	"time"

	"github.com/daeuniverse/dae/common"
	"github.com/daeuniverse/dae/component/sniffing"
)

const (
	PacketSnifferTtl = 3 * time.Second
)

type PacketSniffer struct {
	*sniffing.Sniffer
	deadlineTimer *time.Timer
	Mu            sync.Mutex
}

// PacketSnifferPool is a full-cone udp conn pool
type PacketSnifferPool struct {
	pool             sync.Map
	snifferKeyLocker *common.ShardedKeyLocker[PacketSnifferKey]
}
type PacketSnifferOptions struct {
	Ttl time.Duration
}

type PacketSnifferKey = AddrPortPair

var DefaultPacketSnifferSessionMgr = NewPacketSnifferPool()

func NewPacketSnifferPool() *PacketSnifferPool {
	return &PacketSnifferPool{
		snifferKeyLocker: common.NewShardedKeyLocker(1024, AddrPortPairShard),
	}
}

func (p *PacketSnifferPool) Remove(key PacketSnifferKey) (err error) {
	if ue, ok := p.pool.LoadAndDelete(key); ok {
		sniffer := ue.(*PacketSniffer)
		sniffer.deadlineTimer.Stop()
		sniffer.Close()
	}
	return nil
}

func (p *PacketSnifferPool) Get(key PacketSnifferKey) *PacketSniffer {
	_qs, ok := p.pool.Load(key)
	if !ok {
		return nil
	}
	return _qs.(*PacketSniffer)
}

// GetOrCreate returns the sniffer registered for key, creating it (and arming
// its TTL timer) on first use. Concurrency contract: callers that sniff or
// close a returned sniffer must hold PacketSniffer.Mu — sniffPkt takes it for
// the whole sniff, and the timer's expire takes it before closing — so a
// sniffer can never be closed underneath an in-flight sniff.
func (p *PacketSnifferPool) GetOrCreate(key PacketSnifferKey, createOption *PacketSnifferOptions) (qs *PacketSniffer, isNew bool) {
	_qs, ok := p.pool.Load(key)
	if !ok {
		l := p.snifferKeyLocker.Lock(key)
		defer l.Unlock()

		_qs, ok = p.pool.Load(key)
		if ok {
			return _qs.(*PacketSniffer), false
		}
		// Create an PacketSniffer.
		if createOption == nil {
			createOption = &PacketSnifferOptions{}
		}
		if createOption.Ttl == 0 {
			createOption.Ttl = PacketSnifferTtl
		}

		qs = &PacketSniffer{
			Sniffer:       sniffing.NewPacketSniffer(nil, createOption.Ttl),
			Mu:            sync.Mutex{},
			deadlineTimer: nil,
		}
		qs.deadlineTimer = time.AfterFunc(createOption.Ttl, func() {
			p.expire(key, qs)
		})
		_qs = qs
		p.pool.Store(key, qs)
		// Receive UDP messages.
		isNew = true
	}
	return _qs.(*PacketSniffer), isNew
}

// expire is the TTL timer callback: it removes key from the pool and closes
// the sniffer if it is still the registered one. Close runs under qs.Mu — the
// same mutex that guards an in-flight sniff — because quicKeys owns pooled
// buffers whose Close returns them to the shared pool: an unsynchronized
// close racing a sniff could close the same *Keys twice (double-put), leaving
// two pool entries aliasing one buffer for unrelated future consumers.
func (p *PacketSnifferPool) expire(key PacketSnifferKey, qs *PacketSniffer) {
	l := p.snifferKeyLocker.Lock(key)
	defer l.Unlock()
	_qs, ok := p.pool.LoadAndDelete(key)
	if !ok || _qs.(*PacketSniffer) != qs {
		// The sniffer was already removed (and closed) by Remove, or replaced
		// after removal; nothing to expire.
		return
	}
	qs.Mu.Lock()
	qs.Close()
	qs.Mu.Unlock()
}
