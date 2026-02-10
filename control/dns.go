/*
*  SPDX-License-Identifier: AGPL-3.0-only
*  Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"sync"
	"sync/atomic"
	"time"

	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/common/netutils"
	"github.com/daeuniverse/dae/component/dns"
	"github.com/daeuniverse/outbound/pool"
	"github.com/daeuniverse/quic-go"
	"github.com/daeuniverse/quic-go/http3"
	dnsmessage "github.com/miekg/dns"
	log "github.com/sirupsen/logrus"
)

const (
	udpFailsToSuspend  = 10
	reviveAfterTimeMin = 5 * time.Minute
	reviveAfterTimeMax = 30 * time.Minute
	reviveExtendRatio  = 3
)

var (
	UdpPoolSize = 10
	UdpPoolTtl  = 10 * time.Minute
	TcpPoolSize = 3
	TcpPoolTtl  = 60 * time.Second
)

// TODO: Connection reuse
type DnsForwarder interface {
	ForwardDNS(data []byte) ([]byte, error)
}

func newDnsForwarder(upstream *dns.Upstream, dialArgument dialArgument) (DnsForwarder, error) {
	forwarder, err := func() (DnsForwarder, error) {
		if upstream.Scheme == dns.UpstreamScheme_TCP_UDP {
			// Despite of the network of dialArgument, always use both tcp and udp.
			// The DnsManager will try both and could fallback to tcp if udp is failed for N times.
			doTcp := NewTcpForwarder(dialArgument)
			doUdp := NewUdpForwarder(dialArgument)
			return &DoTcpAndUdp{doTcp: doTcp, doUdp: doUdp}, nil
		}
		switch dialArgument.networkType.L4Proto {
		case consts.L4ProtoStr_TCP:
			switch upstream.Scheme {
			case dns.UpstreamScheme_TCP, dns.UpstreamScheme_TCP_UDP:
				return NewTcpForwarder(dialArgument), nil
			case dns.UpstreamScheme_TLS:
				return &DoTLS{Upstream: *upstream, dialArgument: dialArgument}, nil
			case dns.UpstreamScheme_HTTPS:
				return &DoH{Upstream: *upstream, dialArgument: dialArgument, http3: false}, nil
			default:
				return nil, fmt.Errorf("unexpected scheme: %v", upstream.Scheme)
			}
		case consts.L4ProtoStr_UDP:
			switch upstream.Scheme {
			case dns.UpstreamScheme_UDP, dns.UpstreamScheme_TCP_UDP:
				return NewUdpForwarder(dialArgument), nil
			case dns.UpstreamScheme_QUIC:
				return &DoQ{Upstream: *upstream, dialArgument: dialArgument}, nil
			case dns.UpstreamScheme_H3:
				return &DoH{Upstream: *upstream, dialArgument: dialArgument, http3: true}, nil
			default:
				return nil, fmt.Errorf("unexpected scheme: %v", upstream.Scheme)
			}
		default:
			return nil, fmt.Errorf("unexpected l4proto: %v", dialArgument.networkType.L4Proto)
		}
	}()
	if err != nil {
		return nil, err
	}
	return forwarder, nil
}

type DoH struct {
	dns.Upstream
	dialArgument dialArgument
	http3        bool
}

func (d *DoH) ForwardDNS(data []byte) ([]byte, error) {
	var roundTripper http.RoundTripper
	if d.http3 {
		roundTripper = d.getHttp3RoundTripper()
	} else {
		roundTripper = d.getHttpRoundTripper()
	}
	client := &http.Client{
		Transport: roundTripper,
	}
	serverURL := &url.URL{
		Scheme: "https",
		Host:   d.dialArgument.Target.String(),
		Path:   d.Upstream.Path,
	}

	msg := &dnsmessage.Msg{}
	if err := msg.Unpack(data); err != nil {
		return nil, err
	}
	if err := netutils.ResolveHttp(client, serverURL, msg); err != nil {
		return nil, err
	}
	return msg.Pack()
}

func (d *DoH) getHttpRoundTripper() *http.Transport {
	httpTransport := http.Transport{
		TLSClientConfig: &tls.Config{
			ServerName:         d.Upstream.Hostname,
			InsecureSkipVerify: false,
		},
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			conn, err := d.dialArgument.Dialer.DialContext(ctx, "tcp", d.dialArgument.Target.String())
			if err != nil {
				return nil, err
			}
			return conn, nil
		},
	}

	return &httpTransport
}

func (d *DoH) getHttp3RoundTripper() *http3.RoundTripper {
	roundTripper := &http3.RoundTripper{
		TLSClientConfig: &tls.Config{
			ServerName:         d.Upstream.Hostname,
			NextProtos:         []string{"h3"},
			InsecureSkipVerify: false,
		},
		QUICConfig: &quic.Config{},
		Dial: func(ctx context.Context, addr string, tlsCfg *tls.Config, cfg *quic.Config) (quic.EarlyConnection, error) {
			udpAddr := net.UDPAddrFromAddrPort(d.dialArgument.Target)
			conn, err := d.dialArgument.Dialer.ListenPacket(ctx, d.dialArgument.Target.String())
			if err != nil {
				return nil, err
			}
			c, e := quic.DialEarly(ctx, conn, udpAddr, tlsCfg, cfg)
			return c, e
		},
	}
	return roundTripper
}

type DoQ struct {
	dns.Upstream
	dialArgument dialArgument
	conn         quic.Connection
}

func (d *DoQ) ForwardDNS(data []byte) (resp []byte, err error) {
	if d.conn == nil || d.conn.Context().Err() != nil {
		ctx, cancel := context.WithTimeout(context.TODO(), consts.DefaultDialTimeout)
		defer cancel()
		d.conn, err = d.createConnection(ctx)
		if err != nil {
			return
		}
	}

	defer func() {
		if err != nil {
			d.Close()
		}
	}()

	stream, err := d.conn.OpenStream()
	if err != nil {
		return
	}

	defer stream.Close()
	msg := &dnsmessage.Msg{}
	if err = msg.Unpack(data); err != nil {
		return
	}
	if err := netutils.ResolveStream(stream, msg, true); err != nil {
		return nil, err
	}
	return msg.Pack()
}

func (c *DoQ) Close() error {
	if c.conn != nil {
		c.conn.CloseWithError(0x101, "")
	}
	return nil
}

func (d *DoQ) createConnection(ctx context.Context) (quic.EarlyConnection, error) {
	conn, err := d.dialArgument.Dialer.ListenPacket(ctx, d.dialArgument.Target.String())
	if err != nil {
		return nil, err
	}

	tlsCfg := &tls.Config{
		NextProtos:         []string{"doq"},
		InsecureSkipVerify: false,
		ServerName:         d.Upstream.Hostname,
	}
	addr := net.UDPAddrFromAddrPort(d.dialArgument.Target)
	return quic.DialEarly(ctx, conn, addr, tlsCfg, nil)
}

type DoTLS struct {
	dns.Upstream
	dialArgument dialArgument
}

func (d *DoTLS) ForwardDNS(data []byte) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.TODO(), consts.DefaultDialTimeout)
	defer cancel()
	conn, err := d.dialArgument.Dialer.DialContext(ctx, "tcp", d.dialArgument.Target.String())
	if err != nil {
		return nil, err
	}
	tlsConn := tls.Client(conn, &tls.Config{
		InsecureSkipVerify: false,
		ServerName:         d.Upstream.Hostname,
	})
	if err = tlsConn.Handshake(); err != nil {
		return nil, err
	}

	defer tlsConn.Close()
	msg := &dnsmessage.Msg{}
	if err := msg.Unpack(data); err != nil {
		return nil, err
	}
	if err := netutils.ResolveStream(conn, msg, false); err != nil {
		return nil, err
	}
	return msg.Pack()
}

type DoTcpOrUdp struct {
	dialArgument dialArgument
	dnsManager   []*DnsManager
	network      string // "tcp" or "udp"
	mu           []sync.Mutex
	next         int32
	active       int32
	timer        *time.Timer
	timerMu      sync.Mutex
	ttl          time.Duration
}

func NewTcpForwarder(dialArg dialArgument) *DoTcpOrUdp {
	return &DoTcpOrUdp{
		dialArgument: dialArg,
		network:      "tcp",
		dnsManager:   make([]*DnsManager, TcpPoolSize),
		mu:           make([]sync.Mutex, TcpPoolSize),
		ttl:          TcpPoolTtl,
	}
}

func NewUdpForwarder(dialArg dialArgument) *DoTcpOrUdp {
	return &DoTcpOrUdp{
		dialArgument: dialArg,
		network:      "udp",
		dnsManager:   make([]*DnsManager, UdpPoolSize),
		mu:           make([]sync.Mutex, UdpPoolSize),
		ttl:          UdpPoolTtl,
	}
}

// TODO: Connection reuse
func (d *DoTcpOrUdp) ForwardDNS(data []byte) (resp []byte, err error) {
	// Retry once on net.ErrClosed which may happen when race condition between DnsManager's Resolve() and read().
	maxRetries := 1
	for i := 0; i <= maxRetries; i++ {
		resp, err = d.forwardDnsWithContext(context.Background(), data)
		if !errors.Is(err, net.ErrClosed) {
			break
		}
	}
	return resp, err
}

func (d *DoTcpOrUdp) forwardDnsWithContext(ctx context.Context, data []byte) ([]byte, error) {
	if atomic.SwapInt32(&d.active, 1) == 0 {
		d.timerMu.Lock()
		if d.timer == nil {
			var t *time.Timer
			t = time.AfterFunc(d.ttl, func() {
				d.timerMu.Lock()
				defer d.timerMu.Unlock()
				if atomic.SwapInt32(&d.active, 0) == 0 {
					d.closeDnsManagers()
					d.timer = nil
				} else {
					t.Reset(d.ttl)
				}
			})
			d.timer = t
		}
		d.timerMu.Unlock()
	}
	index := atomic.LoadInt32(&d.next)
	atomic.CompareAndSwapInt32(&d.next, index, (index+1)%int32(len(d.mu)))
	d.mu[index].Lock()
	if d.dnsManager[index] == nil || d.dnsManager[index].IsClosed() {
		ctxTimeout, cancel := context.WithTimeout(ctx, consts.DefaultDialTimeout)
		conn, err := d.dialArgument.Dialer.DialContext(ctxTimeout, d.network, d.dialArgument.Target.String())
		cancel()
		if err != nil {
			d.mu[index].Unlock()
			return nil, err
		}
		d.dnsManager[index] = NewDnsManager(conn, d.network == "tcp", d.dialArgument.Dialer.Name)
	}
	mgr := d.dnsManager[index]
	d.mu[index].Unlock()

	resp, err := mgr.Resolve(ctx, data)
	if errors.Is(err, net.ErrClosed) {
		mgr.Close()
	}
	return resp, err
}

func (d *DoTcpOrUdp) closeDnsManagers() (err error) {
	count := 0
	for i := range d.mu {
		d.mu[i].Lock()
		if d.dnsManager[i] != nil {
			if !d.dnsManager[i].IsClosed() {
				err = d.dnsManager[i].Close()
				count++
			}
			d.dnsManager[i] = nil
		}
		d.mu[i].Unlock()
	}
	if count > 0 {
		log.Infof("Closed %d %s dns managers, dialer: %s, target: %v",
			count, d.network, d.dialArgument.Dialer.Name, d.dialArgument.Target)
	}
	return
}

func (d *DoTcpOrUdp) Close() (err error) {
	d.timerMu.Lock()
	if d.timer != nil {
		d.timer.Stop()
		d.timer = nil
	}
	d.timerMu.Unlock()
	return d.closeDnsManagers()
}

type DoTcpAndUdp struct {
	doTcp *DoTcpOrUdp
	doUdp *DoTcpOrUdp

	udpFails       int32
	reviveTime     int64
	lastReviveTime int64
}

type dnsResult struct {
	tcp      bool
	respData []byte
	err      error
}

func (d *DoTcpAndUdp) ForwardDNS(data []byte) ([]byte, error) {
	canUseUdp := true
	now := time.Now().Unix()
	rt := atomic.LoadInt64(&d.reviveTime)
	if rt != 0 {
		if now < rt {
			canUseUdp = false
		} else {
			d.maybeReviveUdp()
		}
	}

	n := 1
	if canUseUdp {
		n = 2
	}
	resCh := make(chan dnsResult, n)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() {
		r, err := d.doTcp.forwardDnsWithContext(ctx, data)
		resCh <- dnsResult{true, r, err}
	}()

	if canUseUdp {
		go func() {
			var r []byte
			var e error
			// Note: don't give ctx here, avoid canceling udp to count udp timeouts as fails.
			// Copy data here becauase data could have been recycled while waiting for udp dns timeout.
			dataCopy := pool.GetBuffer(len(data))
			defer pool.PutBuffer(dataCopy)
			copy(dataCopy, data)
			if r, e = d.doUdp.ForwardDNS(dataCopy); e != nil {
				d.maybeSuspendUdp()
			} else {
				d.maybeReviveUdp()
			}
			resCh <- dnsResult{false, r, e}
		}()
	}

	var respData []byte
	var firstErr error
	for i := 0; i < n; i++ {
		res := <-resCh
		if res.err == nil {
			// cancel() only works for the tcp goroutine.
			cancel()
			respData = res.respData
			if log.IsLevelEnabled(log.DebugLevel) {
				qInfo := dnsQueryInfo(data)
				log.Debugf("tcp+udp dns resp, tcp: %v, qname: %v, qtype: %v", res.tcp, qInfo.qname, qInfo.qtype)
			}
			return respData, nil
		}
		firstErr = res.err
	}

	return respData, firstErr
}

func (d *DoTcpAndUdp) maybeSuspendUdp() {
	if fails := atomic.AddInt32(&d.udpFails, 1); fails >= udpFailsToSuspend {
		now := time.Now()
		lrt := atomic.LoadInt64(&d.lastReviveTime)
		stableDuration := now.Sub(time.Unix(lrt, 0))
		reduction := time.Duration(int64(stableDuration) / reviveExtendRatio)
		suspendDuration := max(reviveAfterTimeMin, reviveAfterTimeMax-reduction)
		atomic.StoreInt64(&d.reviveTime, now.Add(suspendDuration).Unix())
		log.Warnf("udp dns consecutive fails %v, suspend for %v, stable duration: %v", fails, suspendDuration, stableDuration)
	}
}

func (d *DoTcpAndUdp) maybeReviveUdp() {
	atomic.StoreInt32(&d.udpFails, 0)
	if atomic.SwapInt64(&d.reviveTime, 0) != 0 {
		atomic.StoreInt32(&d.udpFails, 0)
		atomic.StoreInt64(&d.lastReviveTime, time.Now().Unix())
		log.Warnf("Udp dns revived!")
	}
}

func (d *DoTcpAndUdp) Close() (err error) {
	err = d.doTcp.Close()
	err = d.doUdp.Close()
	return
}
