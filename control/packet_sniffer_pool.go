/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"fmt"
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
	snifferKeyLocker common.KeyLocker[UdpEndpointKey]
}
type PacketSnifferOptions struct {
	Ttl time.Duration
}

var DefaultPacketSnifferSessionMgr = NewPacketSnifferPool()

func NewPacketSnifferPool() *PacketSnifferPool {
	return &PacketSnifferPool{}
}

func (p *PacketSnifferPool) Remove(key UdpEndpointKey, sniffer *PacketSniffer) (err error) {
	if ue, ok := p.pool.LoadAndDelete(key); ok {
		sniffer.Close()
		if ue != sniffer {
			return fmt.Errorf("target udp endpoint is not in the pool")
		}
	}
	return nil
}

func (p *PacketSnifferPool) Get(key UdpEndpointKey) *PacketSniffer {
	_qs, ok := p.pool.Load(key)
	if !ok {
		return nil
	}
	return _qs.(*PacketSniffer)
}

// TODO: 工作原理
func (p *PacketSnifferPool) GetOrCreate(key UdpEndpointKey, createOption *PacketSnifferOptions) (qs *PacketSniffer, isNew bool) {
	_qs, ok := p.pool.Load(key)
begin:
	if !ok {
		l := p.snifferKeyLocker.Lock(key)
		defer p.snifferKeyLocker.Unlock(key, l)

		_qs, ok = p.pool.Load(key)
		if ok {
			goto begin
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
