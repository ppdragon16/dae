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

// TODO: 工作原理
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
			l := p.snifferKeyLocker.Lock(key)
			defer l.Unlock()
			if _qs, ok := p.pool.LoadAndDelete(key); ok {
				if _qs.(*PacketSniffer) == qs {
					qs.Close()
				} else {
					// FIXME: ?
				}
			}
		})
		_qs = qs
		p.pool.Store(key, qs)
		// Receive UDP messages.
		isNew = true
	}
	return _qs.(*PacketSniffer), isNew
}
