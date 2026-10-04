/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"context"
	"net"
	"reflect"
	"testing"
	"unsafe"

	dnsmessage "github.com/miekg/dns"

	"github.com/daeuniverse/dae/component/dns"
	"github.com/daeuniverse/dae/component/outbound/dialer"
	D "github.com/daeuniverse/outbound/dialer"
	"github.com/daeuniverse/outbound/netproxy"
)

type stubProxyDialer struct {
	netproxy.Dialer
}

func (s *stubProxyDialer) Alive() bool  { return true }
func (s *stubProxyDialer) Name() string { return "stub" }
func (s *stubProxyDialer) Dial(network, address string) (net.Conn, error) {
	return nil, nil
}
func (s *stubProxyDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	return nil, nil
}
func (s *stubProxyDialer) ListenPacket(ctx context.Context, address string) (net.PacketConn, error) {
	return nil, nil
}

// newTestDialerWithIpv6 builds a dialer with the noIpv6 state a discovery round
// would have frozen in: true when the network's IPv6 was down at check time
// (the direct dialer's tcp4 primary then never triggers a re-discovery, so the
// state survives for the process lifetime).
func newTestDialerWithIpv6(t *testing.T, ipv6 bool) *dialer.Dialer {
	t.Helper()
	d := dialer.NewDialer(&stubProxyDialer{}, &dialer.GlobalOption{},
		&dialer.Property{Property: D.Property{Name: "stub"}}, false)
	noIpv6Field := reflect.ValueOf(d).Elem().FieldByName("noIpv6")
	if !noIpv6Field.IsValid() {
		t.Fatal("noIpv6 field not found")
	}
	v := uint32(0)
	if !ipv6 {
		v = 1
	}
	*(*uint32)(unsafe.Pointer(noIpv6Field.UnsafeAddr())) = v
	return d
}

// TestRejectAAAAQueryStaticExempt pins that static upstreams are never gated by
// the AAAA/NoIpv6 check: their answers are produced in-process and the dial
// argument they carry (direct, a plumbing dummy) says nothing about whether the
// answer can be served. The frozen noIpv6=true of that dummy used to refuse
// every static AAAA answer while upstream names kept resolving.
func TestRejectAAAAQueryStaticExempt(t *testing.T) {
	noIpv6Dialer := newTestDialerWithIpv6(t, false)
	staticUpstream := &dns.Upstream{Scheme: dns.UpstreamScheme_Static, Hostname: "op"}
	realUpstream := &dns.Upstream{Scheme: "udp", Hostname: "223.5.5.5", Port: 53}

	if rejectAAAAQuery(staticUpstream, noIpv6Dialer, uint16(dnsmessage.TypeAAAA)) {
		t.Fatal("static upstream must not be gated by the dummy dialer's NoIpv6")
	}
	if !rejectAAAAQuery(realUpstream, noIpv6Dialer, uint16(dnsmessage.TypeAAAA)) {
		t.Fatal("real upstream with an IPv6-incapable dialer must reject AAAA")
	}
	ipv6Dialer := newTestDialerWithIpv6(t, true)
	if rejectAAAAQuery(realUpstream, ipv6Dialer, uint16(dnsmessage.TypeAAAA)) {
		t.Fatal("real upstream with an IPv6-capable dialer must not reject AAAA")
	}
	if rejectAAAAQuery(realUpstream, noIpv6Dialer, uint16(dnsmessage.TypeA)) {
		t.Fatal("only AAAA queries are gated")
	}
	if rejectAAAAQuery(realUpstream, nil, uint16(dnsmessage.TypeAAAA)) {
		t.Fatal("nil dialer must not gate (defensive)")
	}
}
