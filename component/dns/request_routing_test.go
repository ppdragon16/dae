/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package dns

import (
	"net/netip"
	"testing"

	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/pkg/config_parser"
	"github.com/daeuniverse/dae/pkg/trie"
)

func buildTestRequestMatcher(t *testing.T, rules []*config_parser.RoutingRule, fallback string) *RequestMatcher {
	t.Helper()
	b, err := NewRequestMatcherBuilder(rules, nil, fallback)
	if err != nil {
		t.Fatalf("NewRequestMatcherBuilder() error = %v", err)
	}
	m, err := b.Build()
	if err != nil {
		t.Fatalf("Build() error = %v", err)
	}
	return m
}

// TestRequestMatcherSipDifferential drives the sip match_set over a grid of sets
// and client addresses and compares it against the expression it replaced: a
// Prefix2bin128 string queried with Trie.HasPrefix. The two must agree for every
// input, including the 4-in-6 widening of IPv4 addresses.
func TestRequestMatcherSipDifferential(t *testing.T) {
	sets := [][]string{
		{"10.0.0.0/8"},
		{"192.168.1.0/24", "172.16.0.0/12"},
		{"0.0.0.0/0"},
		{"0.0.0.0/1"},
		{"100.64.0.0/10"},
		{"2001:db8::/32"},
		{"::ffff:0:0/96", "10.0.0.0/8"},
		{"::/0"},
		{"64:ff9b::/96"},
		{"2001:db8::/128"},
		{"192.168.1.1/32"},
		{"10.0.0.0/8", "192.168.1.0/24", "2001:db8::/32", "::/0"},
		{"0.0.0.0/2"},
		{"128.0.0.0/1"},
	}
	addrStrs := []string{
		"0.0.0.0", "1.2.3.4", "10.1.2.3", "10.255.255.255", "11.1.1.1",
		"100.64.1.1", "172.16.5.9", "192.168.1.1", "192.168.1.0", "192.168.2.1",
		"203.0.113.7", "255.255.255.255",
		"::", "::1", "::ffff:1.2.3.4", "::ffff:10.1.2.3",
		"2001:db8::1", "2001:db9::1", "64:ff9b::1.2.3.4", "fe80::1",
		"ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", "128.0.0.1", "127.255.255.255",
		"::ffff:192.168.1.1",
	}

	for _, cidrs := range sets {
		prefixes := make([]netip.Prefix, 0, len(cidrs))
		for _, c := range cidrs {
			prefixes = append(prefixes, netip.MustParsePrefix(c))
		}
		set, err := trie.NewTrieFromPrefixes(prefixes)
		if err != nil {
			t.Fatalf("NewTrieFromPrefixes(%v): %v", cidrs, err)
		}
		for _, s := range addrStrs {
			ip := netip.MustParseAddr(s)
			want := set.HasPrefix(trie.Prefix2bin128(netip.PrefixFrom(ip, ip.BitLen())))
			if got := matchSourceIpSet(set, ip); got != want {
				t.Errorf("matchSourceIpSet(%v, %v) = %v, want %v", cidrs, s, got, want)
			}
		}
	}
}

// TestRequestMatcherSipEndToEnd pins sip routing through the real matcher,
// including the ipv6 opt-out and mac rules that share the loop.
func TestRequestMatcherSipEndToEnd(t *testing.T) {
	m := buildTestRequestMatcher(t, []*config_parser.RoutingRule{
		testResponseRule("reject", testResponseFunction("mac", "00:11:22:33:44:55")),
		testResponseRule("asis", testResponseFunction("sip", "192.168.1.0/24")),
		testResponseRule("reject", testResponseFunction("sip", "2001:db8::/32")),
	}, "asis")

	macHit := [6]byte{0x00, 0x11, 0x22, 0x33, 0x44, 0x55}

	cases := []struct {
		name  string
		mac   [6]byte
		srcIp netip.Addr
		want  consts.DnsRequestOutboundIndex
	}{
		{"mac-hit", macHit, netip.MustParseAddr("10.0.0.1"), consts.DnsRequestOutboundIndex_Reject},
		{"sip-hit-v4", [6]byte{}, netip.MustParseAddr("192.168.1.5"), consts.DnsRequestOutboundIndex_AsIs},
		{"sip-hit-v6", [6]byte{}, netip.MustParseAddr("2001:db8::1"), consts.DnsRequestOutboundIndex_Reject},
		{"sip-miss-fallback", [6]byte{}, netip.MustParseAddr("10.0.0.1"), consts.DnsRequestOutboundIndex_AsIs},
		{"invalid-src-ip", [6]byte{}, netip.Addr{}, consts.DnsRequestOutboundIndex_AsIs},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := m.Match("", 1, tc.mac, tc.srcIp)
			if err != nil {
				t.Fatalf("Match() error = %v", err)
			}
			if got != tc.want {
				t.Fatalf("Match() = %v, want %v", got, tc.want)
			}
		})
	}
}
