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
	log "github.com/sirupsen/logrus"
)

type UdpHandler func(data []byte, from netip.AddrPort) error

type UdpEndpoint struct {
	conn net.PacketConn
	// mu protects deadlineTimer
	mu            sync.Mutex
	deadlineTimer *time.Timer

	src, dst netip.AddrPort
	af       *Anyfrom

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

type ReadPacketFunc func(buf []byte) (int, netip.AddrPort, error)

func (ue *UdpEndpoint) run() (err error) {
	common.ActiveConnections.With(ue.labels).Inc()
	defer common.ActiveConnections.With(ue.labels).Dec()
	buf := pool.GetBuffer(2048)
	defer pool.PutBuffer(buf)
	var readFunc ReadPacketFunc
	if pc, ok := ue.conn.(PacketConnAddrPort); ok {
		readFunc = pc.ReadFromAddrPort
	} else {
		readFunc = func(buf []byte) (int, netip.AddrPort, error) {
			n, from, err := ue.conn.ReadFrom(buf)
			return n, ToAddrPort(from), err
		}
	}
	for {
		n, from, err := readFunc(buf)
		if err != nil {
			if ue.IsClosed() {
				break
			}
			return oops.Wrapf(err, "failed to ReadFromAddrPort")
		}
		ue.counterTraffic.Add(float64(n))
		atomic.AddInt64(&ue.trafficSinceLastCheck, int64(n))
		// Only print routing for new connection to avoid the log exploded (Quic and BT).
		if !ue.receivedReply && log.IsLevelEnabled(log.InfoLevel) {
			log.Infof("Received UDP packet reply: %v <- %v", ue.src, from)
		}
		if _, err = ue.af.WriteToUDPAddrPort(buf[:n], ue.src); err != nil {
			return err
		}
		ue.receivedReply = true
	}
	DefaultAnyfromPool.Recycle(ue.dst, ue.af)
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
	common.RecyclePrometheusLabels(ue.labels)
	ue.mu.Lock()
	ue.deadlineTimer.Stop()
	ue.mu.Unlock()
	ue.cancel()
	return ue.conn.Close()
}

// UdpEndpointKey is the pool key. Dst=0 for Full-Cone NAT, non-zero for QUIC.
type UdpEndpointKey = AddrPortPair

// UdpEndpointPool is a full-cone udp conn pool
type UdpEndpointPool struct {
	pool                 sync.Map
	UdpEndpointKeyLocker *common.ShardedKeyLocker[UdpEndpointKey]
}

var DefaultUdpEndpointPool = UdpEndpointPool{
	UdpEndpointKeyLocker: common.NewShardedKeyLocker(1024, AddrPortPairShard),
}

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

func (p *UdpEndpointPool) Create(
	key UdpEndpointKey,
	udpConn net.PacketConn,
	src, dst netip.AddrPort,
	initNatTimeout time.Duration) (ue *UdpEndpoint, err error) {
	af, err := DefaultAnyfromPool.Obtain(dst, AnyfromTimeoutDefault)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithCancel(context.Background())
	ue = &UdpEndpoint{
		natTimeout: initNatTimeout,
		ctx:        ctx,
		cancel:     cancel,
		src:        src,
		dst:        dst,
		af:         af,
	}
	ue.conn = udpConn
	ue.deadlineTimer = time.AfterFunc(initNatTimeout, func() {
		if !ue.checkTraffic() {
			p.Remove(key)
		}
	})
	p.pool.Store(key, ue)
	return
}
