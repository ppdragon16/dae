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
	log "github.com/sirupsen/logrus"
)

type UdpHandler func(data []byte, from netip.AddrPort) error

type UdpEndpoint struct {
	UdpEndpointKey
	conn net.PacketConn

	af *Anyfrom

	natTimeout            time.Duration
	bonusNatTimeout       time.Duration
	bonusTraffic          int64
	trafficSinceLastCheck int64

	ctx    context.Context
	cancel context.CancelFunc

	dialer         *dialer.Dialer
	labels         [4]string
	counterTraffic *common.Series
	sniffedDomain  string
	receivedReply  bool
}

type ReadPacketFunc func(buf []byte) (int, netip.AddrPort, error)

func (ue *UdpEndpoint) run() {
	var deadlineTimer *time.Timer
	deadlineTimer = time.AfterFunc(ue.natTimeout, func() {
		if ue.IsClosed() {
			return
		}
		traffic := atomic.SwapInt64(&ue.trafficSinceLastCheck, 0)
		if traffic <= 0 {
			ue.Close()
			return
		}
		newTimeout := ue.natTimeout
		if traffic > ue.bonusTraffic {
			newTimeout = ue.bonusNatTimeout
		}
		deadlineTimer.Reset(newTimeout)
	})

	common.Metrics.ActiveConnections.With4(ue.labels).Inc()
	defer common.Metrics.ActiveConnections.With4(ue.labels).Dec()
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
	var err error
	for {
		n, from, e := readFunc(buf)
		if e != nil {
			if ue.IsClosed() {
				break
			}
			err = common.Wrap(e, "failed to ReadFromAddrPort")
			break
		}
		ue.counterTraffic.Add(int64(n))
		atomic.AddInt64(&ue.trafficSinceLastCheck, int64(n))
		// Only print routing for new connection to avoid the log exploded (Quic and BT).
		if !ue.receivedReply && log.IsLevelEnabled(log.InfoLevel) {
			log.Infof("Received UDP packet reply: %v <- %v", ue.Src, from)
		}
		if _, err = ue.af.WriteToUDPAddrPort(buf[:n], ue.Src); err != nil {
			break
		}
		ue.receivedReply = true
	}
	deadlineTimer.Stop()
	DefaultAnyfromPool.Recycle(ue.Dst, ue.af)
	DefaultUdpEndpointPool.Remove(ue.UdpEndpointKey)
	if err != nil {
		netErr, ok := IsNetError(err)
		if !ok || (!netErr.Timeout() && ue.dialer.NeedAliveState()) {
			err = common.
				In("UdpEndpoint r -> l relay").
				With("Is NetError", ok).
				With("Is Temporary", ok && netErr.Temporary()).
				With("Is Timeout", ok && netErr.Timeout()).
				With("Dialer", ue.dialer.Name).
				Wrap(err)
			if !ok {
				log.Warnf("%+v", err)
			} else if !netErr.Timeout() && ue.dialer.NeedAliveState() {
				common.Metrics.ErrorCount.With4(ue.labels).Inc()
				ue.dialer.ReportUnavailable()
				log.Warnf("%+v", err)
			}
		}
	}
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
	ue.counterTraffic.Add(int64(n))
	return n, err
}

// Close should only called by UdpEndpointPool.Remove
func (ue *UdpEndpoint) Close() error {
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
	initNatTimeout time.Duration) (ue *UdpEndpoint, err error) {
	af, err := DefaultAnyfromPool.Obtain(key.Dst, AnyfromTimeoutDefault)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithCancel(context.Background())
	ue = &UdpEndpoint{
		UdpEndpointKey: key,
		conn:           udpConn,
		natTimeout:     initNatTimeout,
		ctx:            ctx,
		cancel:         cancel,
		af:             af,
	}
	p.pool.Store(key, ue)
	return
}
