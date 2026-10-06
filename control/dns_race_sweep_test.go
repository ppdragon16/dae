/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"context"
	"hash/maphash"
	"net"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	dnsmessage "github.com/miekg/dns"

	"github.com/daeuniverse/dae/common"
	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/component/dns"
	"github.com/daeuniverse/dae/component/outbound"
	"github.com/daeuniverse/dae/component/outbound/dialer"
	D "github.com/daeuniverse/outbound/dialer"
	"github.com/daeuniverse/outbound/netproxy"
)

type raceStubProxy struct{ netproxy.Dialer }

func (s *raceStubProxy) Alive() bool                                    { return true }
func (s *raceStubProxy) Name() string                                   { return "race-stub" }
func (s *raceStubProxy) Dial(network, address string) (net.Conn, error) { return nil, nil }
func (s *raceStubProxy) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	return nil, nil
}
func (s *raceStubProxy) ListenPacket(ctx context.Context, address string) (net.PacketConn, error) {
	return nil, nil
}

// raceTestAnswer builds a NOERROR response whose single A record answers ip.
func raceTestAnswer(t testing.TB, name string, ip netip.Addr) []byte {
	t.Helper()
	msg := &dnsmessage.Msg{}
	msg.SetQuestion(name+".", dnsmessage.TypeA)
	msg.Response = true
	msg.RecursionAvailable = true
	msg.Answer = append(msg.Answer, &dnsmessage.A{
		Hdr: dnsmessage.RR_Header{
			Name:   name + ".",
			Rrtype: dnsmessage.TypeA,
			Class:  dnsmessage.ClassINET,
			Ttl:    300,
		},
		A: ip.AsSlice(),
	})
	b, err := msg.Pack()
	if err != nil {
		t.Fatalf("pack: %v", err)
	}
	return b
}

func raceTestUpstream(ip string) *dns.Upstream {
	return &dns.Upstream{Scheme: "udp", Hostname: ip, Port: 53}
}

// TestRaceCacheSweepServesFirstMemberInConfigOrder pins the deterministic
// cache sweep: when every race member already holds a cached answer, the query
// is served from the member the config lists FIRST on every single query —
// not from whichever cache read happens to win a goroutine race. Under the
// sweep the answer is deterministic; without it the winner is random and this
// test fails within the 30 iterations.
func TestRaceCacheSweepServesFirstMemberInConfigOrder(t *testing.T) {
	common.InitMetrics()
	option := &dialer.GlobalOption{
		CheckDnsOptionRaw: dialer.CheckDnsOptionRaw{Raw: []string{"1.1.1.1:53"}},
		CheckInterval:     time.Hour,
	}

	dialerA := dialer.NewDialer(&raceStubProxy{}, option, &dialer.Property{Property: D.Property{Name: "a"}}, false)
	dialerB := dialer.NewDialer(&raceStubProxy{}, option, &dialer.Property{Property: D.Property{Name: "b"}}, false)
	newGroup := func(name string, d *dialer.Dialer) *outbound.DialerGroup {
		return outbound.NewDialerGroup(option, name, []*dialer.Dialer{d}, []*dialer.Annotation{{}},
			dialer.DialerSelectionPolicy{Policy: consts.DialerSelectionPolicy_Fixed, FixedIndex: 0},
			func(alive bool, networkType *common.NetworkType) {})
	}
	groupA := newGroup("grp-a", dialerA)
	groupB := newGroup("grp-b", dialerB)

	upA := raceTestUpstream("1.1.1.1")
	upB := raceTestUpstream("8.8.8.8")
	c := &DnsController{
		enableCache:      true,
		dnsCache:         NewCommonDnsCache(),
		dnsCacheHashSeed: maphash.MakeSeed(),
		routing:          &dns.Dns{}, // HasResponseRules() == false
		matchBitmap:      func(string, []uint32) {},
		bestDialerChooser: func(req *dnsRequest, upstream *dns.Upstream, outArg *dialArgument) error {
			if upstream == upA {
				outArg.Outbound, outArg.Dialer = groupA, dialerA
			} else {
				outArg.Outbound, outArg.Dialer = groupB, dialerB
			}
			outArg.networkType = common.NETWORK_UDP4
			return nil
		},
	}

	const qname = "raced.example.com"
	keyA := c.GetHashKey(qname, uint16(dnsmessage.TypeA), groupA, dialerA)
	keyB := c.GetHashKey(qname, uint16(dnsmessage.TypeA), groupB, dialerB)
	ipA := netip.MustParseAddr("198.51.100.10")
	ipB := netip.MustParseAddr("203.0.113.20")
	c.dnsCache.Save(keyA, raceTestAnswer(t, qname, ipA), 600, false)
	c.dnsCache.Save(keyB, raceTestAnswer(t, qname, ipB), 600, false)
	// Consume the IsNew flag of both entries: the "new answer" epilogue in
	// handleDNSRequestByUpstream updates the eBPF lookup cache, which this
	// test has no core for.
	c.dnsCache.Get(keyA)
	c.dnsCache.Get(keyB)

	req := ObtainDnsRequest(
		netip.MustParseAddrPort("192.168.16.129:44081"),
		netip.MustParseAddrPort("8.8.8.8:53"),
		&bpfRoutingResult{}, false)
	defer RecycleDnsRequest(req)
	members := []*dns.Upstream{upA, upB}

	answerIP := func() netip.Addr {
		t.Helper()
		dnsResp := &dnsResponseData{}
		qi := queryInfo{qname: qname, qtype: uint16(dnsmessage.TypeA)}
		groupUpstream := &dns.Upstream{Scheme: dns.UpstreamScheme_Race, Hostname: "race_dns", RaceGroup: &dns.RaceGroup{Tag: "race_dns", Members: members}}
		if err := c.handleDNSRequestByUpstream(raceTestAnswer(t, qname, netip.IPv4Unspecified()), req, qi, groupUpstream, dnsResp); err != nil {
			t.Fatalf("handleDNSRequestByUpstream: %v", err)
		}
		ips, _ := dnsAnswers(dnsResp.respData)
		if len(ips) != 1 {
			t.Fatalf("expected exactly one answer IP, got %v", ips)
		}
		return ips[0]
	}

	// First query: member A is listed first, so its cached answer wins.
	if got := answerIP(); got != ipA {
		t.Fatalf("first query answered %v, want %v (member A first)", got, ipA)
	}
	// Determinism: every subsequent query must serve member A's cache too —
	// the sweep never falls into racing the two cache reads randomly.
	for i := 0; i < 30; i++ {
		if got := answerIP(); got != ipA {
			t.Fatalf("iteration %d answered %v, want stable %v", i, got, ipA)
		}
	}
}

// countingStubProxy counts dials and hands back a pre-closed pipe so writes
// fail fast without any network.
type countingStubProxy struct {
	netproxy.Dialer
	calls atomic.Int32
}

func (s *countingStubProxy) Alive() bool  { return true }
func (s *countingStubProxy) Name() string { return "counting-stub" }

func (s *countingStubProxy) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	s.calls.Add(1)
	client, peer := net.Pipe()
	_ = peer.Close() // pre-closed peer: writes fail immediately
	return client, nil
}

func (s *countingStubProxy) ListenPacket(ctx context.Context, address string) (net.PacketConn, error) {
	return nil, nil
}

// TestRaceExpiredEntriesFallThroughToRacingRefresh pins the optimistic-cache
// behaviour for a race group: when every member's cache entry is expired, the
// sweep must NOT serve the stale answer and stop there. Instead the members
// must all be dialed — the stale answer is served once, while every member's
// background refresh flies on its own (upstream is part of the flight key), so
// the refresh itself races the whole group and the first success repopulates
// the cache.
func TestRaceExpiredEntriesFallThroughToRacingRefresh(t *testing.T) {
	common.InitMetrics()
	option := &dialer.GlobalOption{
		CheckDnsOptionRaw: dialer.CheckDnsOptionRaw{Raw: []string{"1.1.1.1:53"}},
		CheckInterval:     time.Hour,
	}
	proxyA := &countingStubProxy{}
	proxyB := &countingStubProxy{}
	dialerA := dialer.NewDialer(proxyA, option, &dialer.Property{Property: D.Property{Name: "a"}}, false)
	dialerB := dialer.NewDialer(proxyB, option, &dialer.Property{Property: D.Property{Name: "b"}}, false)
	newGroup := func(name string, d *dialer.Dialer) *outbound.DialerGroup {
		return outbound.NewDialerGroup(option, name, []*dialer.Dialer{d}, []*dialer.Annotation{{}},
			dialer.DialerSelectionPolicy{Policy: consts.DialerSelectionPolicy_Fixed, FixedIndex: 0},
			func(alive bool, networkType *common.NetworkType) {})
	}
	groupA := newGroup("grp-a", dialerA)
	groupB := newGroup("grp-b", dialerB)

	upA := raceTestUpstream("1.1.1.1")
	upB := raceTestUpstream("8.8.8.8")
	c := &DnsController{
		enableCache:      true,
		dnsCache:         NewCommonDnsCache(),
		dnsCacheHashSeed: maphash.MakeSeed(),
		routing:          &dns.Dns{},
		matchBitmap:      func(string, []uint32) {},
		bestDialerChooser: func(req *dnsRequest, upstream *dns.Upstream, outArg *dialArgument) error {
			if upstream == upA {
				outArg.Outbound, outArg.Dialer = groupA, dialerA
			} else {
				outArg.Outbound, outArg.Dialer = groupB, dialerB
			}
			outArg.networkType = common.NETWORK_UDP4
			return nil
		},
	}

	const qname = "stale.example.com"
	keyA := c.GetHashKey(qname, uint16(dnsmessage.TypeA), groupA, dialerA)
	keyB := c.GetHashKey(qname, uint16(dnsmessage.TypeA), groupB, dialerB)
	ipA := netip.MustParseAddr("198.51.100.10")
	ipB := netip.MustParseAddr("203.0.113.20")
	c.dnsCache.Save(keyA, raceTestAnswer(t, qname, ipA), 600, false)
	c.dnsCache.Save(keyB, raceTestAnswer(t, qname, ipB), 600, false)
	// Age both entries past their TTL so the sweep sees them as expired.
	for _, key := range []HashKey{keyA, keyB} {
		if e, ok := c.dnsCache.cache.Get(key); ok {
			e.FetchedAt = time.Now().Add(-2 * time.Hour)
		}
	}
	// Consume the IsNew flag of both entries: the "new answer" epilogue in
	// handleDNSRequestByUpstream updates the eBPF lookup cache, which this
	// minimal controller has no core for (same trick as the sweep test).
	c.dnsCache.Get(keyA)
	c.dnsCache.Get(keyB)

	req := ObtainDnsRequest(
		netip.MustParseAddrPort("192.168.16.129:44081"),
		netip.MustParseAddrPort("8.8.8.8:53"),
		&bpfRoutingResult{}, false)
	defer RecycleDnsRequest(req)
	members := []*dns.Upstream{upA, upB}

	dnsResp := &dnsResponseData{}
	qi := queryInfo{qname: qname, qtype: uint16(dnsmessage.TypeA)}
	groupUpstream := &dns.Upstream{Scheme: dns.UpstreamScheme_Race, Hostname: "race_dns", RaceGroup: &dns.RaceGroup{Tag: "race_dns", Members: members}}
	if err := c.handleDNSRequestByUpstream(raceTestAnswer(t, qname, netip.IPv4Unspecified()), req, qi, groupUpstream, dnsResp); err != nil {
		t.Fatalf("handleDNSRequestByUpstream: %v", err)
	}
	served, _ := dnsAnswers(dnsResp.respData)
	if len(served) != 1 {
		t.Fatalf("expected the stale answer to be served, got %v", served)
	}
	// The first member in config order is the one whose expired entry answers,
	// exactly as a fresh entry would: a stale answer must not depend on which
	// member happened to be probed first at runtime.
	if served[0] != ipA {
		t.Fatalf("stale answer served from %v, want member A's %v", served[0], ipA)
	}

	// Both members must have been dialed: the stale serve must not have
	// stopped the group-wide background refresh.
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if proxyA.calls.Load() >= 1 && proxyB.calls.Load() >= 1 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if a, b := proxyA.calls.Load(), proxyB.calls.Load(); a < 1 || b < 1 {
		t.Fatalf("refresh did not race the group: dialer a calls=%d, dialer b calls=%d", a, b)
	}
}

// TestRaceMissForwardsOnEveryMember pins the flat request phase on a cache
// miss: every member of the group is sent concurrently (none is skipped as
// "not first"), and when all of them fail the round reports an aggregated error
// rather than silently answering nothing.
func TestRaceMissForwardsOnEveryMember(t *testing.T) {
	common.InitMetrics()
	option := &dialer.GlobalOption{
		CheckDnsOptionRaw: dialer.CheckDnsOptionRaw{Raw: []string{"1.1.1.1:53"}},
		CheckInterval:     time.Hour,
	}
	proxyA := &countingStubProxy{}
	proxyB := &countingStubProxy{}
	dialerA := dialer.NewDialer(proxyA, option, &dialer.Property{Property: D.Property{Name: "a"}}, false)
	dialerB := dialer.NewDialer(proxyB, option, &dialer.Property{Property: D.Property{Name: "b"}}, false)
	newGroup := func(name string, d *dialer.Dialer) *outbound.DialerGroup {
		return outbound.NewDialerGroup(option, name, []*dialer.Dialer{d}, []*dialer.Annotation{{}},
			dialer.DialerSelectionPolicy{Policy: consts.DialerSelectionPolicy_Fixed, FixedIndex: 0},
			func(alive bool, networkType *common.NetworkType) {})
	}
	groupA := newGroup("grp-a", dialerA)
	groupB := newGroup("grp-b", dialerB)

	upA := raceTestUpstream("1.1.1.1")
	upB := raceTestUpstream("8.8.8.8")
	c := &DnsController{
		enableCache:      true,
		dnsCache:         NewCommonDnsCache(),
		dnsCacheHashSeed: maphash.MakeSeed(),
		routing:          &dns.Dns{},
		matchBitmap:      func(string, []uint32) {},
		bestDialerChooser: func(req *dnsRequest, upstream *dns.Upstream, outArg *dialArgument) error {
			if upstream == upA {
				outArg.Outbound, outArg.Dialer = groupA, dialerA
			} else {
				outArg.Outbound, outArg.Dialer = groupB, dialerB
			}
			outArg.networkType = common.NETWORK_UDP4
			return nil
		},
	}
	req := ObtainDnsRequest(
		netip.MustParseAddrPort("192.168.16.129:44081"),
		netip.MustParseAddrPort("8.8.8.8:53"),
		&bpfRoutingResult{}, false)
	defer RecycleDnsRequest(req)
	members := []*dns.Upstream{upA, upB}
	groupUpstream := &dns.Upstream{Scheme: dns.UpstreamScheme_Race, Hostname: "race_dns", RaceGroup: &dns.RaceGroup{Tag: "race_dns", Members: members}}

	const qname = "miss.example.com"
	dnsResp := &dnsResponseData{}
	qi := queryInfo{qname: qname, qtype: uint16(dnsmessage.TypeA)}
	// The stub dialers hand back pre-closed pipes, so every member fails; the
	// round must still have tried all of them and report the failure.
	if err := c.handleDNSRequestByUpstream(raceTestAnswer(t, qname, netip.IPv4Unspecified()), req, qi, groupUpstream, dnsResp); err == nil {
		t.Fatalf("expected an aggregated failure, got nil")
	}
	if a, b := proxyA.calls.Load(), proxyB.calls.Load(); a < 1 || b < 1 {
		t.Fatalf("race miss did not forward on every member: dialer a calls=%d, dialer b calls=%d", a, b)
	}
}
