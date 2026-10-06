/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package dns

import (
	"context"
	"net/netip"
	"net/url"
	"slices"
	"testing"

	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/pkg/config_parser"
	"github.com/daeuniverse/dae/pkg/trie"

	dnsmessage "github.com/miekg/dns"
	"strings"
)

func testResponseRule(outbound string, andFunctions ...*config_parser.Function) *config_parser.RoutingRule {
	return &config_parser.RoutingRule{
		AndFunctions: andFunctions,
		Outbound:     config_parser.Function{Name: outbound},
	}
}

func testResponseFunction(name string, values ...string) *config_parser.Function {
	params := make([]*config_parser.Param, 0, len(values))
	for _, v := range values {
		params = append(params, &config_parser.Param{Val: v})
	}
	return &config_parser.Function{Name: name, Params: params}
}

func buildTestResponseMatcher(t *testing.T, rules []*config_parser.RoutingRule, fallback string) *ResponseMatcher {
	t.Helper()
	b, err := NewResponseMatcherBuilder(rules, nil, fallback, nil)
	if err != nil {
		t.Fatalf("NewResponseMatcherBuilder() error = %v", err)
	}
	m, err := b.Build()
	if err != nil {
		t.Fatalf("Build() error = %v", err)
	}
	return m
}

func TestResponseMatcherMacAndSip(t *testing.T) {
	m := buildTestResponseMatcher(t, []*config_parser.RoutingRule{
		testResponseRule("reject", testResponseFunction("mac", "00:11:22:33:44:55")),
		testResponseRule("accept", testResponseFunction("sip", "192.168.1.0/24")),
	}, "reject")

	macMatch := [6]byte{0x00, 0x11, 0x22, 0x33, 0x44, 0x55}
	macOther := [6]byte{0x00, 0x11, 0x22, 0x33, 0x44, 0x66}

	cases := []struct {
		name   string
		srcMac [6]byte
		srcIp  netip.Addr
		want   consts.DnsResponseOutboundIndex
	}{
		{"mac-hit", macMatch, netip.MustParseAddr("10.0.0.1"), consts.DnsResponseOutboundIndex_Reject},
		{"sip-hit-ipv4", macOther, netip.MustParseAddr("192.168.1.5"), consts.DnsResponseOutboundIndex_Accept},
		{"sip-miss-fallback", macOther, netip.MustParseAddr("10.0.0.1"), consts.DnsResponseOutboundIndex_Reject},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := m.Match("", 1, nil, consts.DnsRequestOutboundIndex_AsIs, tc.srcMac, tc.srcIp, uint16(dnsmessage.RcodeSuccess))
			if err != nil {
				t.Fatalf("Match() error = %v", err)
			}
			if got != tc.want {
				t.Fatalf("Match() = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestResponseMatcherSipIPv6(t *testing.T) {
	m := buildTestResponseMatcher(t, []*config_parser.RoutingRule{
		testResponseRule("reject", testResponseFunction("sip", "2001:db8::/32")),
	}, "accept")

	got, err := m.Match("", 1, nil, consts.DnsRequestOutboundIndex_AsIs, [6]byte{}, netip.MustParseAddr("2001:db8::1"), uint16(dnsmessage.RcodeSuccess))
	if err != nil {
		t.Fatalf("Match() error = %v", err)
	}
	if got != consts.DnsResponseOutboundIndex_Reject {
		t.Fatalf("Match() = %v, want %v", got, consts.DnsResponseOutboundIndex_Reject)
	}

	// A source IP outside the prefix must fall through to the fallback.
	got, err = m.Match("", 1, nil, consts.DnsRequestOutboundIndex_AsIs, [6]byte{}, netip.MustParseAddr("2001:db9::1"), uint16(dnsmessage.RcodeSuccess))
	if err != nil {
		t.Fatalf("Match() error = %v", err)
	}
	if got != consts.DnsResponseOutboundIndex_Accept {
		t.Fatalf("Match() = %v, want %v", got, consts.DnsResponseOutboundIndex_Accept)
	}
}

func TestResponseSelectPassesClientIdentity(t *testing.T) {
	m := buildTestResponseMatcher(t, []*config_parser.RoutingRule{
		testResponseRule("reject", testResponseFunction("mac", "00:11:22:33:44:55")),
	}, "accept")

	s := &Dns{
		respMatcher:    m,
		upstream2Index: map[*Upstream]int{nil: int(consts.DnsRequestOutboundIndex_AsIs)},
	}

	macMatch := [6]byte{0x00, 0x11, 0x22, 0x33, 0x44, 0x55}
	idx, up, err := s.ResponseSelect("example.com", 1, nil, 0, nil, macMatch, netip.MustParseAddr("10.0.0.1"))
	if err != nil {
		t.Fatalf("ResponseSelect() error = %v", err)
	}
	if idx != consts.DnsResponseOutboundIndex_Reject {
		t.Fatalf("ResponseSelect() index = %v, want %v", idx, consts.DnsResponseOutboundIndex_Reject)
	}
	if up != nil {
		t.Fatalf("ResponseSelect() upstream = %v, want nil for reserved outbound", up)
	}
}

// TestMatchIpSetDifferential drives the IpSet and SourceIpSet match paths over a
// grid of sets and addresses and compares them against the expressions they
// replaced (a []string of Prefix2bin128 output + trie.Trie.HasPrefix). The two
// must agree bit for bit: matching decides which DNS upstream a response goes to.
func TestMatchIpSetDifferential(t *testing.T) {
	sets := [][]string{
		{"10.0.0.0/8"},
		{"192.168.1.0/24", "172.16.0.0/12"},
		{"0.0.0.0/0"},
		{"0.0.0.0/1"},
		{"2001:db8::/32"},
		{"::ffff:0:0/96", "10.0.0.0/8"},
		{"255.255.255.255/32", "0.0.0.1/32"},
		{"2001:db8:1234::/48", "2001:db8::/64"},
		{"::/0"},
		{"64:ff9b::/96"},
		{"2001:db8::/128"},
	}
	addrStrs := []string{
		"0.0.0.0", "1.2.3.4", "10.1.2.3", "10.255.255.255", "11.1.1.1",
		"172.16.5.9", "192.168.1.1", "192.168.2.1", "203.0.113.7", "255.255.255.255",
		"::", "::1", "::ffff:1.2.3.4", "::ffff:10.1.2.3", "::ffff:192.168.1.1",
		"2001:db8::1", "2001:db8:1234::5", "2001:db9::1", "64:ff9b::1.2.3.4",
		"fe80::1", "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff",
	}
	addrs := make([]netip.Addr, 0, len(addrStrs))
	for _, s := range addrStrs {
		addrs = append(addrs, netip.MustParseAddr(s))
	}
	lists := [][]netip.Addr{nil}
	for _, a := range addrs {
		lists = append(lists, []netip.Addr{a})
	}
	// Lists where only a later element matches, to pin the "any" semantics.
	lists = append(lists,
		[]netip.Addr{netip.MustParseAddr("203.0.113.7"), netip.MustParseAddr("10.1.2.3")},
		[]netip.Addr{netip.MustParseAddr("203.0.113.7"), netip.MustParseAddr("2001:db8::1")},
	)

	for _, cidrs := range sets {
		prefixes := make([]netip.Prefix, 0, len(cidrs))
		for _, c := range cidrs {
			prefixes = append(prefixes, netip.MustParsePrefix(c))
		}
		set, err := trie.NewTrieFromPrefixes(prefixes)
		if err != nil {
			t.Fatalf("NewTrieFromPrefixes(%v): %v", cidrs, err)
		}
		for _, ips := range lists {
			ref := make([]string, 0, len(ips))
			for _, ip := range ips {
				ref = append(ref, trie.Prefix2bin128(netip.PrefixFrom(netip.AddrFrom16(ip.As16()), 128)))
			}
			want := slices.ContainsFunc(ref, set.HasPrefix)
			if got := matchIpSet(set, ips); got != want {
				t.Errorf("matchIpSet(%v, %v) = %v, want %v", cidrs, ips, got, want)
			}
		}
		for _, ip := range addrs {
			want := set.HasPrefix(trie.Prefix2bin128(netip.PrefixFrom(ip, ip.BitLen())))
			if got := matchSourceIpSet(set, ip); got != want {
				t.Errorf("matchSourceIpSet(%v, %v) = %v, want %v", cidrs, ip, got, want)
			}
		}
	}
}

// TestResponseMatcherIpSetEndToEnd pins IpSet routing through the real matcher,
// including the case where only the last resolved address is in the set.
func TestResponseMatcherIpSetEndToEnd(t *testing.T) {
	m := buildTestResponseMatcher(t, []*config_parser.RoutingRule{
		testResponseRule("reject", testResponseFunction("ip", "10.0.0.0/8")),
		testResponseRule("reject", testResponseFunction("ip", "192.168.0.0/16")),
		testResponseRule("reject", testResponseFunction("ip", "2001:db8::/32")),
	}, "accept")

	cases := []struct {
		name string
		ips  []netip.Addr
		want consts.DnsResponseOutboundIndex
	}{
		{"v4-hit-last-element", []netip.Addr{
			netip.MustParseAddr("93.184.216.34"),
			netip.MustParseAddr("192.168.1.5"),
		}, consts.DnsResponseOutboundIndex_Reject},
		{"v6-hit", []netip.Addr{
			netip.MustParseAddr("2001:db8::1"),
		}, consts.DnsResponseOutboundIndex_Reject},
		{"miss", []netip.Addr{
			netip.MustParseAddr("93.184.216.34"),
		}, consts.DnsResponseOutboundIndex_Accept},
		{"v6-miss", []netip.Addr{
			netip.MustParseAddr("2001:db9::1"),
		}, consts.DnsResponseOutboundIndex_Accept},
		{"no-addresses", nil, consts.DnsResponseOutboundIndex_Accept},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := m.Match("", 1, tc.ips, consts.DnsRequestOutboundIndex_AsIs, [6]byte{}, netip.Addr{}, uint16(dnsmessage.RcodeSuccess))
			if err != nil {
				t.Fatalf("Match() error = %v", err)
			}
			if got != tc.want {
				t.Fatalf("Match() = %v, want %v", got, tc.want)
			}
		})
	}
}

// TestResponseMatcherUpstreamCoversViaDesugaredNames pins that a response rule
// written with the bare upstream name also matches responses attributed to the
// via-desugared virtual entries: race(cf_dns, g_dns, via: us) answers carry
// cf_dns(us)/g_dns(us), not cf_dns/g_dns. Without the expansion the bare-name
// rule silently never matched race responses.
func TestResponseMatcherUpstreamCoversViaDesugaredNames(t *testing.T) {
	upstreamName2Id := map[string]uint8{
		"cf_dns":     5,
		"cf_dns(us)": 7,
		"g_dns":      6,
		"g_dns(us)":  8,
	}
	rules := []*config_parser.RoutingRule{
		testResponseRule("accept", testResponseFunction("upstream", "cf_dns", "g_dns")),
	}
	b, err := NewResponseMatcherBuilder(rules, upstreamName2Id, "reject", nil)
	if err != nil {
		t.Fatalf("NewResponseMatcherBuilder() error = %v", err)
	}
	m, err := b.Build()
	if err != nil {
		t.Fatalf("Build() error = %v", err)
	}

	match := func(from uint8) consts.DnsResponseOutboundIndex {
		t.Helper()
		idx, err := m.Match("x.example.com.", uint16(dnsmessage.TypeA), nil, consts.DnsRequestOutboundIndex(from), [6]byte{}, netip.Addr{}, uint16(dnsmessage.RcodeSuccess))
		if err != nil {
			t.Fatalf("Match(from=%d): %v", from, err)
		}
		return idx
	}

	// Responses from both via-desugared virtual entries hit the rule (accept).
	if idx := match(7); idx != consts.DnsResponseOutboundIndex_Accept {
		t.Fatalf("from cf_dns(us): got %v, want accept", idx)
	}
	if idx := match(8); idx != consts.DnsResponseOutboundIndex_Accept {
		t.Fatalf("from g_dns(us): got %v, want accept", idx)
	}
	// The bare entry is covered too.
	if idx := match(5); idx != consts.DnsResponseOutboundIndex_Accept {
		t.Fatalf("from cf_dns: got %v, want accept", idx)
	}
	// An unrelated upstream falls through to the fallback (reject), proving the
	// rule matched on upstream identity rather than accepting everything.
	if idx := match(9); idx != consts.DnsResponseOutboundIndex_Reject {
		t.Fatalf("from other: got %v, want reject (fallback)", idx)
	}
}

// TestResponseMatcherUnknownUpstreamName pins the error surface of the
// upstream() matcher: a name that is neither defined nor a via-desugared base
// must fail the build instead of silently matching nothing.
func TestResponseMatcherUnknownUpstreamName(t *testing.T) {
	rules := []*config_parser.RoutingRule{
		testResponseRule("accept", testResponseFunction("upstream", "nope")),
	}
	_, err := NewResponseMatcherBuilder(rules, map[string]uint8{"cf_dns": 5}, "reject", nil)
	if err == nil || !strings.Contains(err.Error(), "not found") {
		t.Fatalf("expected not-found error, got %v", err)
	}
}
func mustURL(t *testing.T, raw string) *url.URL {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatalf("url.Parse(%q): %v", raw, err)
	}
	return u
}

func TestResponseMatcherRCode(t *testing.T) {
	rules := []*config_parser.RoutingRule{
		testResponseRule("accept", testResponseFunction("rcode", "nxdomain", "servfail")),
	}
	b, err := NewResponseMatcherBuilder(rules, nil, "reject", nil)
	if err != nil {
		t.Fatalf("NewResponseMatcherBuilder() error = %v", err)
	}
	m, err := b.Build()
	if err != nil {
		t.Fatalf("Build() error = %v", err)
	}
	cases := []struct {
		name  string
		rcode uint16
		want  consts.DnsResponseOutboundIndex
	}{
		{"nxdomain", uint16(dnsmessage.RcodeNameError), consts.DnsResponseOutboundIndex_Accept},
		{"servfail", uint16(dnsmessage.RcodeServerFailure), consts.DnsResponseOutboundIndex_Accept},
		{"noerror", uint16(dnsmessage.RcodeSuccess), consts.DnsResponseOutboundIndex_Reject},
		{"refused", uint16(dnsmessage.RcodeRefused), consts.DnsResponseOutboundIndex_Reject},
	}
	for _, tc := range cases {
		idx, err := m.Match("x.example.com.", uint16(dnsmessage.TypeA), nil, consts.DnsRequestOutboundIndex_AsIs, [6]byte{}, netip.Addr{}, tc.rcode)
		if err != nil {
			t.Fatalf("%s: Match: %v", tc.name, err)
		}
		if idx != tc.want {
			t.Fatalf("%s: got %v, want %v", tc.name, idx, tc.want)
		}
	}
}

// TestResponseSelectRCodeNxdomainAccept pins the end-to-end contract through
// ResponseSelect: an NXDOMAIN from a non-race upstream is accepted (not
// re-resolved) when an rcode rule says so, while a NOERROR response from the
// same upstream still falls to the fallback.
func TestResponseSelectRCodeNxdomainAccept(t *testing.T) {
	member, err := NewUpstream(context.Background(), mustURL(t, "udp://1.1.1.1:53"), "")
	if err != nil {
		t.Fatalf("member: %v", err)
	}
	member2, err := NewUpstream(context.Background(), mustURL(t, "udp://8.8.8.8:53"), "")
	if err != nil {
		t.Fatalf("member2: %v", err)
	}
	s := &Dns{
		upstream: []*UpstreamResolver{
			{Raw: mustURL(t, "udp://1.1.1.1:53"), upstream: member, init: 1},
			{Raw: mustURL(t, "udp://8.8.8.8:53"), upstream: member2, init: 1}, // re-resolve target at index 1
		},
	}
	rules := []*config_parser.RoutingRule{
		testResponseRule("accept", testResponseFunction("rcode", "nxdomain")),
		testResponseRule("g_dns", testResponseFunction("upstream", "cf_dns")),
	}
	b, err := NewResponseMatcherBuilder(rules, map[string]uint8{"cf_dns": 0, "g_dns": 1}, "reject", nil)
	if err != nil {
		t.Fatalf("NewResponseMatcherBuilder: %v", err)
	}
	s.respMatcher, err = b.Build()
	if err != nil {
		t.Fatalf("Build: %v", err)
	}

	// NXDOMAIN from the member upstream: the rcode rule accepts it before the
	// race rule can send it around again.
	idx, _, err := s.ResponseSelect("gone.example.com.", uint16(dnsmessage.TypeA), nil, uint16(dnsmessage.RcodeNameError), member, [6]byte{}, netip.MustParseAddr("192.168.1.5"))
	if err != nil {
		t.Fatalf("ResponseSelect(nxdomain): %v", err)
	}
	if idx != consts.DnsResponseOutboundIndex_Accept {
		t.Fatalf("nxdomain: got %v, want accept", idx)
	}

	// NOERROR with answers from the same member: the upstream rule matches and
	// hands back g_dns for re-resolution.
	idx, up, err := s.ResponseSelect("x.example.com.", uint16(dnsmessage.TypeA), []netip.Addr{netip.MustParseAddr("1.2.3.4")}, uint16(dnsmessage.RcodeSuccess), member, [6]byte{}, netip.MustParseAddr("192.168.1.5"))
	if err != nil {
		t.Fatalf("ResponseSelect(noerror): %v", err)
	}
	if up == nil || up.Scheme != "udp" || up.Hostname != "8.8.8.8" {
		t.Fatalf("noerror: expected the g_dns upstream, got %+v", up)
	}
	if idx != consts.DnsResponseOutboundIndex(1) {
		t.Fatalf("noerror: got index %d, want 1", idx)
	}
}

// TestResponseMatcherExpandsRaceGroupTag pins that upstream(<race tag>) expands
// to the group's member ids. Responses are attributed to the answering member
// (upstream2Index), never to the group placeholder, so without the expansion the
// rule compiles but can never fire - and its negation would always fire.
func TestResponseMatcherExpandsRaceGroupTag(t *testing.T) {
	ctx := context.Background()
	memberCf, err := NewUpstream(ctx, mustURL(t, "udp://1.1.1.1:53"), "")
	if err != nil {
		t.Fatalf("member cf: %v", err)
	}
	memberG, err := NewUpstream(ctx, mustURL(t, "udp://8.8.8.8:53"), "")
	if err != nil {
		t.Fatalf("member g: %v", err)
	}
	other, err := NewUpstream(ctx, mustURL(t, "udp://223.5.5.5:53"), "")
	if err != nil {
		t.Fatalf("other: %v", err)
	}
	s := &Dns{
		upstream: []*UpstreamResolver{
			{Raw: mustURL(t, "udp://1.1.1.1:53"), upstream: memberCf, init: 1}, // 0: cf_dns
			{Raw: mustURL(t, "udp://8.8.8.8:53"), upstream: memberG, init: 1},  // 1: g_dns
			{Raw: mustURL(t, "race://race_dns")},                               // 2: placeholder
			{Raw: mustURL(t, "udp://223.5.5.5:53"), upstream: other, init: 1},  // 3: cn_dns
		},
		raceGroupIndices: map[uint8][]uint8{2: {0, 1}},
		upstream2Index:   map[*Upstream]int{memberCf: 0, memberG: 1, other: 3},
	}
	rules := []*config_parser.RoutingRule{
		testResponseRule("reject", testResponseFunction("upstream", "race_dns")),
	}
	b, err := NewResponseMatcherBuilder(rules,
		map[string]uint8{"cf_dns": 0, "g_dns": 1, "race_dns": 2, "cn_dns": 3}, "accept",
		map[string][]uint8{"race_dns": {0, 1}})
	if err != nil {
		t.Fatalf("NewResponseMatcherBuilder: %v", err)
	}
	s.respMatcher, err = b.Build()
	if err != nil {
		t.Fatalf("Build: %v", err)
	}

	ips := []netip.Addr{netip.MustParseAddr("1.2.3.4")}
	for _, tc := range []struct {
		name       string
		from       *Upstream
		wantReject bool
	}{
		{"cf_dns member", memberCf, true},
		{"g_dns member", memberG, true},
		{"unrelated upstream", other, false},
	} {
		idx, _, err := s.ResponseSelect("x.example.com.", uint16(dnsmessage.TypeA), ips,
			uint16(dnsmessage.RcodeSuccess), tc.from, [6]byte{}, netip.MustParseAddr("192.168.1.5"))
		if err != nil {
			t.Fatalf("%s: ResponseSelect: %v", tc.name, err)
		}
		gotReject := idx == consts.DnsResponseOutboundIndex_Reject
		if gotReject != tc.wantReject {
			t.Fatalf("%s: reject=%v, want %v", tc.name, gotReject, tc.wantReject)
		}
	}
}
