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
