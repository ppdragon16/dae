/*
*  SPDX-License-Identifier: AGPL-3.0-only
*  Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/daeuniverse/dae/component/outbound/dialer"
)

type Anyfrom struct {
	*net.UDPConn
	deadlineTimer *time.Timer
	ttl           time.Duration
	refCount      int32
}

// AnyfromPool is a full-cone udp listener pool
type AnyfromPool struct {
	pool    map[netip.AddrPort]*Anyfrom
	mu      sync.RWMutex
	afReqCh chan *afRequest
}

var DefaultAnyfromPool *AnyfromPool = nil

func NewAnyfromPool() *AnyfromPool {
	return &AnyfromPool{
		pool:    make(map[netip.AddrPort]*Anyfrom, 64),
		afReqCh: make(chan *afRequest, 128),
	}
}

type afResponse struct {
	conn *net.UDPConn
	err  error
}

type afRequest struct {
	lAddr   string
	afResCh chan *afResponse
}

func (p *AnyfromPool) Start(ctx context.Context) {
	lc := net.ListenConfig{
		Control: func(network string, address string, c syscall.RawConn) error {
			return dialer.TransparentControl(c)
		},
		KeepAlive: 0,
	}
	GetDaeNetns().With(func() error {
		defer func() {
			p.mu.Lock()
			defer p.mu.Unlock()
			for _, af := range p.pool {
				if af.deadlineTimer != nil {
					af.deadlineTimer.Stop()
				}
				af.Close()
			}
			p.pool = make(map[netip.AddrPort]*Anyfrom)
		}()
		for {
			select {
			case <-ctx.Done():
				return nil
			case req, ok := <-p.afReqCh:
				if !ok {
					return nil
				}
				pc, err := lc.ListenPacket(ctx, "udp", req.lAddr)
				if err != nil {
					req.afResCh <- &afResponse{conn: nil, err: err}
				} else {
					req.afResCh <- &afResponse{conn: pc.(*net.UDPConn), err: nil}
				}
			}
		}
	})
}

func (p *AnyfromPool) createAnyfrom(lAddr netip.AddrPort, ttl time.Duration) (*Anyfrom, error) {
	afResCh := make(chan *afResponse, 1)
	p.afReqCh <- &afRequest{lAddr: lAddr.String(), afResCh: afResCh}
	select {
	case afRes := <-afResCh:
		if afRes.err != nil {
			return nil, afRes.err
		}

		initialRefCount := int32(1)
		if ttl == 0 {
			// zero-ttl means "immortal".
			initialRefCount = 2
		}
		af := &Anyfrom{
			UDPConn:  afRes.conn,
			ttl:      ttl,
			refCount: initialRefCount,
		}

		p.pool[lAddr] = af
		return af, nil
	case <-time.After(1 * time.Second):
		return nil, errors.New("timeout to create UDP conn for Anyfrom")
	}
}

func (p *AnyfromPool) Obtain(lAddr netip.AddrPort, ttl time.Duration) (conn *Anyfrom, err error) {
	p.mu.RLock()
	af, ok := p.pool[lAddr]
	if ok {
		atomic.AddInt32(&af.refCount, 1)
		p.mu.RUnlock()
		return af, nil
	}
	p.mu.RUnlock()

	p.mu.Lock()
	defer p.mu.Unlock()

	if af, ok = p.pool[lAddr]; ok {
		atomic.AddInt32(&af.refCount, 1)
		return af, nil
	}

	return p.createAnyfrom(lAddr, ttl)
}

func (p *AnyfromPool) Recycle(lAddr netip.AddrPort, af *Anyfrom) {
	if atomic.AddInt32(&af.refCount, -1) > 0 {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if af.deadlineTimer != nil {
		af.deadlineTimer.Reset(af.ttl)
	} else {
		af.deadlineTimer = time.AfterFunc(af.ttl, func() {
			if atomic.LoadInt32(&af.refCount) > 0 {
				return
			}
			p.mu.Lock()
			defer p.mu.Unlock()
			if atomic.LoadInt32(&af.refCount) <= 0 {
				if p.pool[lAddr] == af {
					delete(p.pool, lAddr)
				}
				af.Close()
			}
		})
	}
}
