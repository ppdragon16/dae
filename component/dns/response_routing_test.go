/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package dns

import (
	"net/netip"
	"slices"
	"testing"

	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/pkg/config_parser"
	"github.com/daeuniverse/dae/pkg/trie"
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
	b, err := NewResponseMatcherBuilder(rules, nil, fallback)
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
			got, err := m.Match("", 1, nil, consts.DnsRequestOutboundIndex_AsIs, tc.srcMac, tc.srcIp)
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

	got, err := m.Match("", 1, nil, consts.DnsRequestOutboundIndex_AsIs, [6]byte{}, netip.MustParseAddr("2001:db8::1"))
	if err != nil {
		t.Fatalf("Match() error = %v", err)
	}
	if got != consts.DnsResponseOutboundIndex_Reject {
		t.Fatalf("Match() = %v, want %v", got, consts.DnsResponseOutboundIndex_Reject)
	}

	// A source IP outside the prefix must fall through to the fallback.
	got, err = m.Match("", 1, nil, consts.DnsRequestOutboundIndex_AsIs, [6]byte{}, netip.MustParseAddr("2001:db9::1"))
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
	idx, up, err := s.ResponseSelect("example.com", 1, nil, nil, macMatch, netip.MustParseAddr("10.0.0.1"))
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
			got, err := m.Match("", 1, tc.ips, consts.DnsRequestOutboundIndex_AsIs, [6]byte{}, netip.Addr{})
			if err != nil {
				t.Fatalf("Match() error = %v", err)
			}
			if got != tc.want {
				t.Fatalf("Match() = %v, want %v", got, tc.want)
			}
		})
	}
}
