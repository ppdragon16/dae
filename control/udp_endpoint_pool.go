/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"context"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"github.com/daeuniverse/dae/common"
	"github.com/daeuniverse/dae/component/outbound/dialer"
	"github.com/daeuniverse/outbound/pool"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/samber/oops"
)

type UdpHandler func(data []byte, from netip.AddrPort) error

type UdpEndpoint struct {
	conn net.PacketConn
	// mu protects deadlineTimer
	mu            sync.Mutex
	deadlineTimer *time.Timer
	handler       UdpHandler

	natTimeout            time.Duration
	bonusNatTimeout       time.Duration
	bonusTraffic          int64
	trafficSinceLastCheck int64

	ctx    context.Context
	cancel context.CancelFunc

	dialer         *dialer.Dialer
	labels         prometheus.Labels
	counterTraffic prometheus.Counter
	sniffedDomain  string
	receivedReply  bool
}

func (ue *UdpEndpoint) run() error {
	common.ActiveConnections.With(ue.labels).Inc()
	defer common.ActiveConnections.With(ue.labels).Dec()
	buf := pool.GetBuffer(2048)
	defer pool.PutBuffer(buf)
	if pc, ok := ue.conn.(PacketConnAddrPort); ok {
		return ue.runWithAddrPort(pc, buf)
	}
	return ue.runWithAddr(ue.conn, buf)
}

func (ue *UdpEndpoint) runWithAddr(pc net.PacketConn, buf []byte) error {
	for {
		n, from, err := pc.ReadFrom(buf)
		if err != nil {
			if ue.IsClosed() {
				break
			}
			return oops.Wrapf(err, "failed to ReadFrom")
		}
		ue.counterTraffic.Add(float64(n))
		atomic.AddInt64(&ue.trafficSinceLastCheck, int64(n))
		if err = ue.handler(buf[:n], ToAddrPort(from)); err != nil {
			return err
		}
		ue.receivedReply = true
	}
	return nil
}

func (ue *UdpEndpoint) runWithAddrPort(pc PacketConnAddrPort, buf []byte) error {
	for {
		n, from, err := pc.ReadFromAddrPort(buf)
		if err != nil {
			if ue.IsClosed() {
				break
			}
			return oops.Wrapf(err, "failed to ReadFromAddrPort")
		}
		ue.counterTraffic.Add(float64(n))
		atomic.AddInt64(&ue.trafficSinceLastCheck, int64(n))
		if err = ue.handler(buf[:n], from); err != nil {
			return err
		}
		ue.receivedReply = true
	}
	return nil
}

func (ue *UdpEndpoint) checkTraffic() bool {
	if ue.IsClosed() {
		return false
	}
	traffic := atomic.SwapInt64(&ue.trafficSinceLastCheck, 0)
	if traffic <= 0 {
		return false
	}
	ue.mu.Lock()
	defer ue.mu.Unlock()
	newTimeout := ue.natTimeout
	if traffic > ue.bonusTraffic {
		newTimeout = ue.bonusNatTimeout
	}
	ue.deadlineTimer.Reset(newTimeout)
	return true
}

func (ue *UdpEndpoint) IsClosed() bool {
	return ue.ctx.Err() != nil
}

func (ue *UdpEndpoint) WriteTo(b []byte, addr netip.AddrPort) (n int, err error) {
	if pc, ok := ue.conn.(PacketConnAddrPort); ok {
		n, err = pc.WriteToAddrPort(b, addr)
	} else {
		n, err = ue.conn.WriteTo(b, net.UDPAddrFromAddrPort(addr))
	}
	ue.counterTraffic.Add(float64(n))
	return n, err
}

// Close should only called by UdpEndpointPool.Remove
func (ue *UdpEndpoint) Close() error {
	ue.mu.Lock()
	ue.deadlineTimer.Stop()
	ue.mu.Unlock()
	ue.cancel()
	return ue.conn.Close()
}

// UdpEndpointKey is the pool key. Dst=0 for Full-Cone NAT, non-zero for QUIC.
type UdpEndpointKey struct {
	Src netip.AddrPort
	Dst netip.AddrPort
}

// UdpEndpointPool is a full-cone udp conn pool
type UdpEndpointPool struct {
	pool                 sync.Map
	UdpEndpointKeyLocker common.KeyLocker[UdpEndpointKey]
}

type UdpEndpointOptions struct {
	PacketConn      net.PacketConn
	Handler         UdpHandler
	InitNatTimeout  time.Duration
	BonusNatTimeout time.Duration
	BonusTraffic    int64

	Dialer *dialer.Dialer
	labels prometheus.Labels

	SniffedDomain string
}

var DefaultUdpEndpointPool = UdpEndpointPool{}

func (p *UdpEndpointPool) Remove(key UdpEndpointKey) (err error) {
	if ue, ok := p.pool.LoadAndDelete(key); ok {
		ue.(*UdpEndpoint).Close()
	}
	return nil
}

func (p *UdpEndpointPool) Get(key UdpEndpointKey) (udpEndpoint *UdpEndpoint, ok bool) {
	_ue, ok := p.pool.Load(key)
	if !ok {
		return nil, ok
	}
	return _ue.(*UdpEndpoint), ok
}

func (p *UdpEndpointPool) Create(key UdpEndpointKey, createOption *UdpEndpointOptions) (udpEndpoint *UdpEndpoint) {
	ctx, cancel := context.WithCancel(context.Background())
	udpEndpoint = &UdpEndpoint{
		conn:            createOption.PacketConn,
		handler:         createOption.Handler,
		natTimeout:      createOption.InitNatTimeout,
		bonusNatTimeout: createOption.BonusNatTimeout,
		bonusTraffic:    createOption.BonusTraffic,
		ctx:             ctx,
		cancel:          cancel,
		dialer:          createOption.Dialer,
		labels:          createOption.labels,
		counterTraffic:  common.TrafficBytes.With(createOption.labels),
		sniffedDomain:   createOption.SniffedDomain,
	}
	udpEndpoint.deadlineTimer = time.AfterFunc(createOption.InitNatTimeout, func() {
		if !udpEndpoint.checkTraffic() {
			p.Remove(key)
		}
	})
	p.pool.Store(key, udpEndpoint)
	return
}
