/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package dns

import (
	"strings"
	"testing"

	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/config"
	"github.com/daeuniverse/dae/pkg/config_parser"
)

func raceViaTestConfig(rules ...*config_parser.RoutingRule) *config.Dns {
	return &config.Dns{
		Upstream: []config.KeyableString{
			"cf4_dns:udp://1.1.1.1:53",
			"g4_dns:udp://8.8.8.8:53",
		},
		Routing: config.DnsRouting{
			Request: config.DnsRequestRouting{
				Rules:    rules,
				Fallback: "asis",
			},
			Response: config.DnsResponseRouting{
				Fallback: "accept",
			},
		},
	}
}

func raceRule(members []string, via string) *config_parser.RoutingRule {
	params := make([]*config_parser.Param, 0, len(members)+1)
	for _, m := range members {
		params = append(params, &config_parser.Param{Val: m})
	}
	if via != "" {
		params = append(params, &config_parser.Param{Key: "via", Val: via})
	}
	return &config_parser.RoutingRule{
		Outbound: config_parser.Function{Name: consts.Function_Race, Params: params},
	}
}

func newForRaceTest(t *testing.T, rules ...*config_parser.RoutingRule) *Dns {
	t.Helper()
	s, err := New(raceViaTestConfig(rules...), &NewOption{
		UpstreamReadyCallback: func(*Upstream) {},
	}, map[string]uint8{"ai": 7, "us": 9})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	return s
}

func soleRaceGroup(t *testing.T, s *Dns) (placeholder uint8, members []uint8) {
	t.Helper()
	if len(s.raceGroupIndices) != 1 {
		t.Fatalf("got %d race groups, want 1", len(s.raceGroupIndices))
	}
	for idx, m := range s.raceGroupIndices {
		placeholder = idx
		members = m
	}
	return placeholder, members
}

// TestRaceViaDesugarsMembersToVirtualUpstreams pins the race(a, b, via: G)
// desugaring: each bare member becomes the virtual upstream "<member>(<G>)"
// (the same identity a standalone "member(via: G)" rule gets), the group
// identity encodes the effective member names, and every member is bound to
// the via outbound at resolution time.
func TestRaceViaDesugarsMembersToVirtualUpstreams(t *testing.T) {
	s := newForRaceTest(t, raceRule([]string{"cf4_dns", "g4_dns"}, "ai"))

	placeholder, members := soleRaceGroup(t, s)
	if len(members) != 2 {
		t.Fatalf("race group has %d members, want 2", len(members))
	}

	// Group identity must encode the effective member names so that
	// race(a, b) and race(a, b, via: ai) stay distinct groups.
	want := "race://cf4_dns(ai),g4_dns(ai)"
	if got := s.upstream[placeholder].Raw.String(); got != want {
		t.Fatalf("race group identity = %q, want %q", got, want)
	}

	ups := s.GetRaceUpstreams(consts.DnsRequestOutboundIndex(placeholder))
	if len(ups) != 2 {
		t.Fatalf("GetRaceUpstreams() returned %d upstreams, want 2", len(ups))
	}
	for i, up := range ups {
		if up.Outbound != consts.OutboundIndex(7) {
			t.Errorf("member %d bound to outbound %v, want ai (7)", i, up.Outbound)
		}
	}
}

// TestRaceViaDeduplicatesWithStandaloneVia pins the identity sharing between
// the desugared race member and a standalone "cf4_dns(via: ai)" rule: the
// race must reuse the existing virtual upstream instead of creating a second
// unbound entry.
func TestRaceViaDeduplicatesWithStandaloneVia(t *testing.T) {
	rules := []*config_parser.RoutingRule{
		{Outbound: config_parser.Function{
			Name:   "cf4_dns",
			Params: []*config_parser.Param{{Key: "via", Val: "ai"}},
		}},
		raceRule([]string{"cf4_dns", "g4_dns"}, "ai"),
	}
	s := newForRaceTest(t, rules...)

	// cf4_dns(ai) [shared], race placeholder, g4_dns(ai). The bare cf4_dns is
	// never instantiated because no rule routes to it unbound.
	if len(s.upstream) != 3 {
		t.Fatalf("got %d upstream entries, want 3", len(s.upstream))
	}
	placeholder, members := soleRaceGroup(t, s)
	if len(members) != 2 {
		t.Fatalf("race group has %d members, want 2", len(members))
	}
	if members[0] == members[1] {
		t.Fatalf("race members collapsed into one entry")
	}
	ups := s.GetRaceUpstreams(consts.DnsRequestOutboundIndex(placeholder))
	for i, up := range ups {
		if up.Outbound != consts.OutboundIndex(7) {
			t.Errorf("member %d bound to outbound %v, want ai (7)", i, up.Outbound)
		}
	}
}

// TestPlainRaceUnbound pins that race(a, b) without via keeps members
// unbound (traffic routing decides the outbound) and keeps the plain group
// identity, i.e. the via feature does not disturb existing configs.
func TestPlainRaceUnbound(t *testing.T) {
	s := newForRaceTest(t, raceRule([]string{"cf4_dns", "g4_dns"}, ""))

	placeholder, members := soleRaceGroup(t, s)
	if len(members) != 2 {
		t.Fatalf("race group has %d members, want 2", len(members))
	}
	if got := s.upstream[placeholder].Raw.String(); got != "race://cf4_dns,g4_dns" {
		t.Fatalf("race group identity = %q, want %q", got, "race://cf4_dns,g4_dns")
	}
	ups := s.GetRaceUpstreams(consts.DnsRequestOutboundIndex(placeholder))
	for i, up := range ups {
		if up.Outbound != consts.OutboundIndex(0xFF) {
			t.Errorf("member %d bound to outbound %v, want unspecified (0xFF)", i, up.Outbound)
		}
	}
}

// TestRaceViaValidation pins the error surface of the syntax.
func TestRaceViaValidation(t *testing.T) {
	cases := []struct {
		name    string
		members []string
		via     string
		wantErr string
	}{
		{"unknown-outbound", []string{"cf4_dns", "g4_dns"}, "nope", `outbound "nope" not found`},
		{"no-members", nil, "ai", "requires at least one upstream member"},
		{"undefined-member", []string{"cf4_dns", "ghost_dns"}, "ai", "undefined upstream name"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := New(raceViaTestConfig(raceRule(tc.members, tc.via)),
				&NewOption{UpstreamReadyCallback: func(*Upstream) {}},
				map[string]uint8{"ai": 7})
			if err == nil {
				t.Fatalf("New() succeeded, want error containing %q", tc.wantErr)
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("error = %v, want it to contain %q", err, tc.wantErr)
			}
		})
	}

	t.Run("duplicate-via", func(t *testing.T) {
		rule := &config_parser.RoutingRule{Outbound: config_parser.Function{
			Name: consts.Function_Race,
			Params: []*config_parser.Param{
				{Val: "cf4_dns"},
				{Key: "via", Val: "ai"},
				{Key: "via", Val: "us"},
			},
		}}
		_, err := New(raceViaTestConfig(rule), &NewOption{UpstreamReadyCallback: func(*Upstream) {}},
			map[string]uint8{"ai": 7, "us": 9})
		if err == nil || !strings.Contains(err.Error(), "at most one via") {
			t.Fatalf("error = %v, want it to mention \"at most one via\"", err)
		}
	})

	t.Run("unsupported-key", func(t *testing.T) {
		rule := &config_parser.RoutingRule{Outbound: config_parser.Function{
			Name: consts.Function_Race,
			Params: []*config_parser.Param{
				{Val: "cf4_dns"},
				{Key: "ttl", Val: "5"},
			},
		}}
		_, err := New(raceViaTestConfig(rule), &NewOption{UpstreamReadyCallback: func(*Upstream) {}},
			map[string]uint8{"ai": 7})
		if err == nil || !strings.Contains(err.Error(), "only accepts bare upstream names and a single via") {
			t.Fatalf("error = %v, want it to mention the accepted syntax", err)
		}
	})
}

// TestRaceViaPositionIndependent pins that the via modifier may appear
// anywhere in the race() argument list (text-level: the ANTLR grammar keeps
// keyed params in place; both config compilers collect members and the via in
// one pass and desugar every member), and that members listed after the via
// are bound as well.
func TestRaceViaPositionIndependent(t *testing.T) {
	conf := `
dns {
	upstream {
		cf4_dns: 'udp://1.1.1.1:53'
		g4_dns: 'udp://8.8.8.8:53'
	}
	routing {
		request {
			qname(suffix:x.com) -> race(cf4_dns, via: ai, g4_dns)
			fallback: asis
		}
	}
}
`
	sections, err := config_parser.Parse(conf)
	if err != nil {
		t.Fatalf("config_parser.Parse() error = %v", err)
	}
	var rule *config_parser.RoutingRule
	var walk func(sec *config_parser.Section)
	walk = func(sec *config_parser.Section) {
		for _, item := range sec.Items {
			switch v := item.Value.(type) {
			case *config_parser.Section:
				walk(v)
			case *config_parser.RoutingRule:
				if v.Outbound.Name == consts.Function_Race {
					rule = v
				}
			}
		}
	}
	for _, sec := range sections {
		walk(sec)
	}
	if rule == nil {
		t.Fatalf("race rule not found in parsed config")
	}

	s := newForRaceTest(t, rule)
	placeholder, members := soleRaceGroup(t, s)
	if len(members) != 2 {
		t.Fatalf("race group has %d members, want 2", len(members))
	}
	if got := s.upstream[placeholder].Raw.String(); got != "race://cf4_dns(ai),g4_dns(ai)" {
		t.Fatalf("race group identity = %q, want %q", got, "race://cf4_dns(ai),g4_dns(ai)")
	}
	ups := s.GetRaceUpstreams(consts.DnsRequestOutboundIndex(placeholder))
	for i, up := range ups {
		if up.Outbound != consts.OutboundIndex(7) {
			t.Errorf("member %d (listed after via) bound to outbound %v, want ai (7)", i, up.Outbound)
		}
	}
}
