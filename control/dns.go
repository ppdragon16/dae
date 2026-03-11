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
	"net/netip"
	"net/url"
	"sync"
	"sync/atomic"
	"time"

	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/common/netutils"
	"github.com/daeuniverse/dae/component/dns"
	"github.com/daeuniverse/dae/component/outbound/dialer"
	"github.com/daeuniverse/dae/config"
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
	ForwardDNS(msg *dnsmessage.Msg) error
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
				return NewDoTLS(upstream, dialArgument), nil
			case dns.UpstreamScheme_HTTPS:
				return NewDoH(upstream, dialArgument, false), nil
			default:
				return nil, fmt.Errorf("unexpected scheme: %v", upstream.Scheme)
			}
		case consts.L4ProtoStr_UDP:
			switch upstream.Scheme {
			case dns.UpstreamScheme_UDP, dns.UpstreamScheme_TCP_UDP:
				return NewUdpForwarder(dialArgument), nil
			case dns.UpstreamScheme_QUIC:
				return NewDoQ(upstream, dialArgument), nil
			case dns.UpstreamScheme_H3:
				return NewDoH(upstream, dialArgument, true), nil
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
	http3     bool
	client    *http.Client
	serverURL *url.URL
}

func NewDoH(upstream *dns.Upstream, dialArgument dialArgument, http3 bool) *DoH {
	var roundTripper http.RoundTripper
	if http3 {
		roundTripper = getHttp3RoundTripper(upstream.Hostname, dialArgument.Dialer, dialArgument.Target)
	} else {
		roundTripper = getHttpRoundTripper(upstream.Hostname, dialArgument.Dialer, dialArgument.Target)
	}
	return &DoH{
		http3:  http3,
		client: &http.Client{Transport: roundTripper},
		serverURL: &url.URL{
			Scheme: "https",
			Host:   dialArgument.Target.String(),
			Path:   upstream.Path,
		},
	}
}

func (d *DoH) ForwardDNS(msg *dnsmessage.Msg) error {
	data, err := msg.Pack()
	if err != nil {
		return err
	}
	resp, err := netutils.ResolveHttp(d.client, d.serverURL, data)
	if err != nil {
		return err
	}
	return msg.Unpack(resp)
}

func (d *DoH) Close() error {
	if d.http3 {
		if tr, ok := d.client.Transport.(*http3.Transport); ok {
			return tr.Close()
		}
	} else {
		if tr, ok := d.client.Transport.(*http.Transport); ok {
			tr.CloseIdleConnections()
		}
	}
	return nil
}

func getHttpRoundTripper(hostname string, dialer *dialer.Dialer, target netip.AddrPort) *http.Transport {
	httpTransport := http.Transport{
		TLSClientConfig: &tls.Config{
			ServerName:         hostname,
			InsecureSkipVerify: false,
		},
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			conn, err := dialer.DialContext(ctx, "tcp", target.String())
			if err != nil {
				return nil, err
			}
			return conn, nil
		},
	}

	return &httpTransport
}

func getHttp3RoundTripper(hostname string, dialer *dialer.Dialer, target netip.AddrPort) *http3.Transport {
	roundTripper := &http3.Transport{
		TLSClientConfig: &tls.Config{
			ServerName:         hostname,
			NextProtos:         []string{"h3"},
			InsecureSkipVerify: false,
		},
		QUICConfig: &quic.Config{
			KeepAlivePeriod: 30 * time.Second,
			MaxIdleTimeout:  45 * time.Second,
		},
		Dial: func(ctx context.Context, addr string, tlsCfg *tls.Config, cfg *quic.Config) (quic.EarlyConnection, error) {
			udpAddr := net.UDPAddrFromAddrPort(target)
			conn, err := dialer.ListenPacket(ctx, target.String())
			if err != nil {
				return nil, err
			}
			c, err := quic.DialEarly(ctx, conn, udpAddr, tlsCfg, cfg)
			if err != nil {
				_ = conn.Close()
				return nil, err
			}
			return c, nil
		},
	}
	return roundTripper
}

type DoQ struct {
	dns.Upstream
	dialArgument dialArgument
	mu           sync.RWMutex
	conn         quic.Connection
}

func NewDoQ(upstream *dns.Upstream, dialArgument dialArgument) *DoQ {
	return &DoQ{
		Upstream:     *upstream,
		dialArgument: dialArgument,
	}
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

func (d *DoQ) getConnection() (quic.Connection, error) {
	d.mu.RLock()
	if d.conn != nil && d.conn.Context().Err() == nil {
		defer d.mu.RUnlock()
		return d.conn, nil
	}
	d.mu.RUnlock()

	d.mu.Lock()
	defer d.mu.Unlock()

	if d.conn != nil && d.conn.Context().Err() == nil {
		return d.conn, nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), consts.DefaultDialTimeout)
	defer cancel()

	conn, err := d.createConnection(ctx)
	if err != nil {
		return nil, err
	}
	d.conn = conn
	return d.conn, nil
}

func (d *DoQ) ForwardDNS(msg *dnsmessage.Msg) error {
	data, err := msg.Pack()
	if err != nil {
		return err
	}
	var conn quic.Connection
	var stream quic.Stream
	conn, err = d.getConnection()
	if err != nil {
		return err
	}

	defer func() {
		if err != nil {
			d.Close()
		}
	}()

	stream, err = conn.OpenStreamSync(context.Background())
	if err != nil {
		return err
	}
	defer stream.Close()

	resp, err := netutils.ResolveStream(stream, data, true)
	if err != nil {
		return err
	}
	return msg.Unpack(resp)
}

func (d *DoQ) Close() error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.conn != nil {
		d.conn.CloseWithError(0x101, "")
		d.conn = nil
	}
	return nil
}

type DoTLS struct {
	dns.Upstream
	dialArgument dialArgument

	pool chan *tls.Conn
}

func NewDoTLS(upstream *dns.Upstream, dialArgument dialArgument) *DoTLS {
	return &DoTLS{
		Upstream:     *upstream,
		dialArgument: dialArgument,
		pool:         make(chan *tls.Conn, TcpPoolSize),
	}
}

func (d *DoTLS) createNewConn() (*tls.Conn, error) {
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

	if err = tlsConn.HandshakeContext(ctx); err != nil {
		conn.Close()
		return nil, err
	}
	return tlsConn, nil
}

func (d *DoTLS) getConn() (*tls.Conn, error) {
	select {
	case conn := <-d.pool:
		return conn, nil
	default:
		return d.createNewConn()
	}
}

func (d *DoTLS) putConn(conn *tls.Conn) {
	select {
	case d.pool <- conn:
	default:
		conn.Close()
	}
}

func (d *DoTLS) ForwardDNS(msg *dnsmessage.Msg) error {
	data, err := msg.Pack()
	if err != nil {
		return err
	}

	conn, err := d.getConn()
	if err != nil {
		return err
	}

	resp, err := netutils.ResolveStream(conn, data, false)
	if err != nil {
		conn.Close()
		return err
	}
	d.putConn(conn)
	return msg.Unpack(resp)
}

func (d *DoTLS) Close() {
	close(d.pool)
	for conn := range d.pool {
		conn.Close()
	}
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
func (d *DoTcpOrUdp) ForwardDNS(msg *dnsmessage.Msg) (err error) {
	// Retry once on net.ErrClosed which may happen when race condition between DnsManager's Resolve() and read().
	maxRetries := 1
	for i := 0; i <= maxRetries; i++ {
		err = d.forwardDnsWithContext(context.Background(), msg)
		if !errors.Is(err, net.ErrClosed) {
			break
		}
	}
	return err
}

func (d *DoTcpOrUdp) forwardDnsWithContext(ctx context.Context, msg *dnsmessage.Msg) error {
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
			return err
		}
		d.dnsManager[index] = NewDnsManager(conn, d.network == "tcp", d.dialArgument.Dialer.Name)
	}
	mgr := d.dnsManager[index]
	d.mu[index].Unlock()

	err := mgr.Resolve(ctx, msg)
	if errors.Is(err, net.ErrClosed) {
		mgr.Close()
	}
	return err
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
	msg *dnsmessage.Msg
	tcp bool
	err error
}

func (d *DoTcpAndUdp) ForwardDNS(msg *dnsmessage.Msg) (err error) {
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
		m := msg.Copy()
		resCh <- dnsResult{m, true, d.doTcp.forwardDnsWithContext(ctx, m)}
	}()

	if canUseUdp {
		go func() {
			m := msg.Copy()
			var e error
			// Note: don't give ctx here, avoid canceling udp to count udp timeouts as fails.
			if e = d.doUdp.ForwardDNS(m); e != nil {
				d.maybeSuspendUdp()
			} else {
				d.maybeReviveUdp()
			}
			resCh <- dnsResult{m, false, e}
		}()
	}

	var firstErr error
	for i := 0; i < n; i++ {
		res := <-resCh
		if res.err == nil {
			// cancel() only works for the tcp goroutine.
			cancel()
			res.msg.CopyTo(msg)
			log.Debugf("tcp+udp dns resp, tcp: %v, qname: %s, qtype: %v", res.tcp, msg.Question[0].Name, msg.Question[0].Qtype)
			return nil
		}
		firstErr = res.err
	}

	return firstErr
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

type StaticForwarder struct {
	getEntryFn func() (*config.DnsStaticEntry, bool)
}

func (s *StaticForwarder) ForwardDNS(msg *dnsmessage.Msg) error {
	if len(msg.Question) == 0 {
		return nil // Return empty response for invalid requests
	}

	q := msg.Question[0]
	qname := q.Name
	qtype := q.Qtype

	var answers []dnsmessage.RR
	entry, ok := s.getEntryFn()
	if !ok {
		return fmt.Errorf("failed to get static entry")
	}
	// Use configured TTL or default (300)
	ttl := entry.TTL
	if ttl == 0 {
		ttl = 300
	}

	// Add A records
	if qtype == dnsmessage.TypeA || qtype == dnsmessage.TypeANY {
		for _, ip := range entry.A {
			addr, err := netip.ParseAddr(ip)
			if err != nil {
				continue
			}
			if !addr.Is4() {
				continue
			}
			answers = append(answers, &dnsmessage.A{
				Hdr: dnsmessage.RR_Header{
					Name:   qname,
					Rrtype: dnsmessage.TypeA,
					Class:  dnsmessage.ClassINET,
					Ttl:    ttl,
				},
				A: addr.AsSlice(),
			})
		}
	}

	// Add AAAA records
	if qtype == dnsmessage.TypeAAAA || qtype == dnsmessage.TypeANY {
		for _, ip := range entry.AAAA {
			addr, err := netip.ParseAddr(ip)
			if err != nil {
				continue
			}
			if !addr.Is6() {
				continue
			}
			answers = append(answers, &dnsmessage.AAAA{
				Hdr: dnsmessage.RR_Header{
					Name:   qname,
					Rrtype: dnsmessage.TypeAAAA,
					Class:  dnsmessage.ClassINET,
					Ttl:    ttl,
				},
				AAAA: addr.AsSlice(),
			})
		}
	}

	// Add TXT records
	if qtype == dnsmessage.TypeTXT || qtype == dnsmessage.TypeANY {
		for _, txt := range entry.TXT {
			answers = append(answers, &dnsmessage.TXT{
				Hdr: dnsmessage.RR_Header{
					Name:   qname,
					Rrtype: dnsmessage.TypeTXT,
					Class:  dnsmessage.ClassINET,
					Ttl:    ttl,
				},
				Txt: []string{txt},
			})
		}
	}

	msg.Answer = answers
	msg.Rcode = dnsmessage.RcodeSuccess
	msg.Response = true
	msg.RecursionAvailable = true
	msg.Truncated = false

	return nil
}
