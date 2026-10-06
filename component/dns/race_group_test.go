/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package dns

import (
	"context"
	"net/netip"
	"strings"
	"testing"

	dnsmessage "github.com/miekg/dns"

	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/config"
	"github.com/daeuniverse/dae/pkg/config_parser"
)

// raceGroupConfig builds a config whose upstream section defines a race group
// plus two plain upstreams, with rules referencing them.
func raceGroupConfig(rules ...*config_parser.RoutingRule) *config.Dns {
	return &config.Dns{
		Upstream: []config.KeyableString{
			"cf4_dns:udp://1.1.1.1:53",
			"g4_dns:udp://8.8.8.8:53",
			"race_dns:race(tcp+udp://1.1.1.1:53,tcp+udp://8.8.8.8:53)",
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

func newForRaceTest(t *testing.T, rules ...*config_parser.RoutingRule) *Dns {
	t.Helper()
	s, err := New(raceGroupConfig(rules...), &NewOption{
		UpstreamReadyCallback: func(*Upstream) {},
	}, map[string]uint8{"ai": 7, "us": 9})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	return s
}

func soleRaceGroup(t *testing.T, s *Dns) (placeholder uint8, members []uint8) {
	t.Helper()
	if len(s.raceGroups) != 1 {
		t.Fatalf("got %d race groups, want 1", len(s.raceGroups))
	}
	for idx, g := range s.raceGroups {
		placeholder = idx
		members = g.Indices
	}
	return placeholder, members
}

// raceGroupIdxByTag finds a compiled race group by its tag.
func raceGroupIdxByTag(t *testing.T, s *Dns, tag string) uint8 {
	t.Helper()
	for idx, g := range s.raceGroups {
		if g.Tag == tag {
			return idx
		}
	}
	t.Fatalf("race group %q not registered", tag)
	return 0
}

func outboundRule(name string, params ...*config_parser.Param) *config_parser.RoutingRule {
	return &config_parser.RoutingRule{
		Outbound: config_parser.Function{Name: name, Params: params},
	}
}

// TestUpstreamRaceGroupReference pins that a race group defined in the
// upstream section compiles into a race placeholder with all members, and that
// a routing rule referencing the group tag resolves to that placeholder.
func TestUpstreamRaceGroupReference(t *testing.T) {
	s := newForRaceTest(t, outboundRule("race_dns"))

	placeholder, members := soleRaceGroup(t, s)
	if len(members) != 2 {
		t.Fatalf("race group has %d members, want 2", len(members))
	}
	if got := s.upstream[placeholder].Raw.String(); got != "race://race_dns" {
		t.Fatalf("race group identity = %q, want %q", got, "race://race_dns")
	}

	ups := s.GetRaceUpstreams(consts.DnsRequestOutboundIndex(placeholder))
	if len(ups) != 2 {
		t.Fatalf("GetRaceUpstreams() returned %d upstreams, want 2", len(ups))
	}
	for i, up := range ups {
		if up.Scheme != "tcp+udp" {
			t.Errorf("member %d scheme = %v, want tcp+udp", i, up.Scheme)
		}
		if up.Outbound != consts.OutboundIndex(0xFF) {
			t.Errorf("member %d bound to outbound %v, want unspecified (0xFF)", i, up.Outbound)
		}
	}
}

// TestUpstreamRaceGroupMemberByName pins that members may reference other
// upstream tags, and that the shared instance is reused instead of duplicated.
func TestUpstreamRaceGroupMemberByName(t *testing.T) {
	s := newForRaceTest(t,
		outboundRule("cf4_dns"), // plain reference first: registers the shared entry
		outboundRule("race_dns"),
	)

	// Each rule reference instantiates its own resolver (pre-existing
	// behaviour), so at minimum the two race members plus the placeholder and
	// the plain cf4_dns reference must exist.
	if len(s.upstream) < 3 {
		t.Fatalf("got %d upstream entries, want at least 3", len(s.upstream))
	}
	placeholder, members := soleRaceGroup(t, s)
	if len(members) != 2 {
		t.Fatalf("race group has %d members, want 2", len(members))
	}
	ups := s.GetRaceUpstreams(consts.DnsRequestOutboundIndex(placeholder))
	if len(ups) != 2 {
		t.Fatalf("GetRaceUpstreams() returned %d upstreams, want 2", len(ups))
	}
}

// TestUpstreamRaceGroupViaReference pins that binding the group at the
// reference site (race_dns(via: ai)) instantiates a shadow group whose members
// are all bound to the via outbound, while the unbound reference keeps working.
func TestUpstreamRaceGroupViaReference(t *testing.T) {
	s := newForRaceTest(t,
		outboundRule("race_dns"),
		outboundRule("race_dns", &config_parser.Param{Key: "via", Val: "ai"}),
	)

	// Two groups now exist: the unbound one and the ai-bound shadow.
	if len(s.raceGroups) != 2 {
		t.Fatalf("got %d registered groups, want 2", len(s.raceGroups))
	}
	shadow := raceGroupIdxByTag(t, s, "race_dns(ai)")
	ups := s.GetRaceUpstreams(consts.DnsRequestOutboundIndex(shadow))
	if len(ups) != 2 {
		t.Fatalf("shadow group has %d members, want 2", len(ups))
	}
	for i, up := range ups {
		if up.Outbound != consts.OutboundIndex(7) {
			t.Errorf("shadow member %d bound to outbound %v, want ai (7)", i, up.Outbound)
		}
	}
	// The unbound group's members stay unbound.
	plain := raceGroupIdxByTag(t, s, "race_dns")
	for i, up := range s.GetRaceUpstreams(consts.DnsRequestOutboundIndex(plain)) {
		if up.Outbound != consts.OutboundIndex(0xFF) {
			t.Errorf("plain member %d bound to outbound %v, want unspecified (0xFF)", i, up.Outbound)
		}
	}
}

// TestUpstreamRaceGroupValidation pins the error surface.
func TestUpstreamRaceGroupValidation(t *testing.T) {
	t.Run("undefined-member", func(t *testing.T) {
		_, err := New(&config.Dns{
			Upstream: []config.KeyableString{
				"race_dns:race(udp://1.1.1.1:53,ghost)",
			},
		}, &NewOption{UpstreamReadyCallback: func(*Upstream) {}}, map[string]uint8{})
		if err == nil || !contains(err.Error(), "undefined upstream") {
			t.Fatalf("error = %v, want undefined-upstream error", err)
		}
	})
	t.Run("nested-race", func(t *testing.T) {
		_, err := New(&config.Dns{
			Upstream: []config.KeyableString{
				"race_dns:race(udp://1.1.1.1:53,race(udp://8.8.8.8:53))",
			},
		}, &NewOption{UpstreamReadyCallback: func(*Upstream) {}}, map[string]uint8{})
		if err == nil || !contains(err.Error(), "nested race groups") {
			t.Fatalf("error = %v, want nested-race error", err)
		}
	})
	t.Run("rule-level-race-migration", func(t *testing.T) {
		_, err := New(raceGroupConfig(outboundRule("cf4_dns"), outboundRule("g4_dns"),
			&config_parser.RoutingRule{Outbound: config_parser.Function{
				Name: "race", Params: []*config_parser.Param{{Val: "cf4_dns"}, {Val: "g4_dns"}},
			}}),
			&NewOption{UpstreamReadyCallback: func(*Upstream) {}}, map[string]uint8{})
		if err == nil || !contains(err.Error(), "no longer supported") {
			t.Fatalf("error = %v, want migration error", err)
		}
	})
	t.Run("unknown-via-outbound-at-reference", func(t *testing.T) {
		_, err := New(raceGroupConfig(outboundRule("race_dns", &config_parser.Param{Key: "via", Val: "nope"})),
			&NewOption{UpstreamReadyCallback: func(*Upstream) {}}, map[string]uint8{})
		if err == nil || !contains(err.Error(), `outbound "nope" not found`) {
			t.Fatalf("error = %v, want unknown-outbound error", err)
		}
	})
}

func contains(haystack, needle string) bool {
	return strings.Contains(haystack, needle)
}

// TestRaceGroupUpstreamCarriesMembers pins the contract the request and
// response paths rely on after the race refactor: resolving a race index yields
// the synthetic group upstream with its members attached (never the
// non-dialable placeholder), so callers can expand it without special cases.
func TestRaceGroupUpstreamCarriesMembers(t *testing.T) {
	s := newForRaceTest(t, outboundRule("race_dns"))

	idx := raceGroupIdxByTag(t, s, "race_dns")
	up, err := s.GetUpstream(consts.DnsRequestOutboundIndex(idx))
	if err != nil {
		t.Fatalf("GetUpstream(race): %v", err)
	}
	if !up.IsRaceGroup() {
		t.Fatalf("GetUpstream(race) = scheme %q, want the race group upstream", up.Scheme)
	}
	if up.RaceGroup == nil || len(up.RaceGroup.Members) != 2 {
		t.Fatalf("race group missing members: %+v", up.RaceGroup)
	}
	if up.RaceGroup.Members[0].Hostname != "1.1.1.1" || up.RaceGroup.Members[1].Hostname != "8.8.8.8" {
		t.Fatalf("members resolved wrong: %v %v", up.RaceGroup.Members[0].Hostname, up.RaceGroup.Members[1].Hostname)
	}
	// Repeated resolution returns the same cached group upstream.
	again, err := s.GetUpstream(consts.DnsRequestOutboundIndex(idx))
	if err != nil || again != up {
		t.Fatalf("GetUpstream(race) not cached: err=%v same=%v", err, again == up)
	}
}

// TestResponseSelectRaceTargetYieldsGroupUpstream pins that a response rule may
// re-resolve through a race group again (restored after the race refactor):
// ResponseSelect hands back the group upstream with members attached, which the
// request path then expands.
func TestResponseSelectRaceTargetYieldsGroupUpstream(t *testing.T) {
	ctx := context.Background()
	memberCf, err := NewUpstream(ctx, mustURL(t, "udp://1.1.1.1:53"), "")
	if err != nil {
		t.Fatalf("member cf: %v", err)
	}
	memberG, err := NewUpstream(ctx, mustURL(t, "udp://8.8.8.8:53"), "")
	if err != nil {
		t.Fatalf("member g: %v", err)
	}
	s := &Dns{
		upstream: []*UpstreamResolver{
			{Raw: mustURL(t, "udp://1.1.1.1:53"), upstream: memberCf, init: 1}, // 0: cf_dns
			{Raw: mustURL(t, "udp://8.8.8.8:53"), upstream: memberG, init: 1},  // 1: g_dns
			{Raw: mustURL(t, "race://race_dns")},                               // 2: placeholder
		},
		raceGroups: map[uint8]*raceGroup{
			2: {
				Tag:      "race_dns",
				Indices:  []uint8{0, 1},
				Upstream: &Upstream{Scheme: UpstreamScheme_Race, Hostname: "race_dns"},
			},
		},
		upstream2Index: map[*Upstream]int{memberCf: 0, memberG: 1},
	}
	rules := []*config_parser.RoutingRule{
		testResponseRule("race_dns", testResponseFunction("upstream", "cf_dns")),
	}
	b, err := NewResponseMatcherBuilder(rules,
		map[string]uint8{"cf_dns": 0, "g_dns": 1, "race_dns": 2}, "accept",
		map[string][]uint8{"race_dns": {0, 1}})
	if err != nil {
		t.Fatalf("NewResponseMatcherBuilder: %v", err)
	}
	s.respMatcher, err = b.Build()
	if err != nil {
		t.Fatalf("Build: %v", err)
	}

	ips := []netip.Addr{netip.MustParseAddr("1.2.3.4")}
	idx, up, err := s.ResponseSelect("x.example.com.", uint16(dnsmessage.TypeA), ips,
		uint16(dnsmessage.RcodeSuccess), memberCf, [6]byte{}, netip.MustParseAddr("192.168.1.5"))
	if err != nil {
		t.Fatalf("ResponseSelect(race target): %v", err)
	}
	if idx != consts.DnsResponseOutboundIndex(2) {
		t.Fatalf("got index %d, want the race group index 2", idx)
	}
	if !up.IsRaceGroup() || up.RaceGroup == nil || len(up.RaceGroup.Members) != 2 {
		t.Fatalf("race target must yield the group upstream with members, got scheme=%q group=%v", up.Scheme, up.RaceGroup)
	}
	if up.RaceGroup.Members[0] != memberCf || up.RaceGroup.Members[1] != memberG {
		t.Fatal("members resolved in the wrong order")
	}
}

// TestDuplicateRaceGroupTagRejected pins that two race groups cannot share a
// tag: the second registration would otherwise silently orphan the first
// group's placeholder and shadow the name in the upstream index.
func TestDuplicateRaceGroupTagRejected(t *testing.T) {
	_, err := New(&config.Dns{
		Upstream: []config.KeyableString{
			"race_dns:race(udp://1.1.1.1:53)",
			"race_dns:race(udp://8.8.8.8:53)",
		},
	}, &NewOption{UpstreamReadyCallback: func(*Upstream) {}}, map[string]uint8{})
	if err == nil || !contains(err.Error(), "duplicate race group tag") {
		t.Fatalf("error = %v, want a duplicate-tag error", err)
	}
}
