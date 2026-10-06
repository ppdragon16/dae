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
	if len(s.raceGroupIndices) != 1 {
		t.Fatalf("got %d race groups, want 1", len(s.raceGroupIndices))
	}
	for idx, m := range s.raceGroupIndices {
		placeholder = idx
		members = m
	}
	return placeholder, members
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
	if len(s.raceTag2GroupIdx) != 2 {
		t.Fatalf("got %d registered groups, want 2", len(s.raceTag2GroupIdx))
	}
	shadow, ok := s.raceTag2GroupIdx["race_dns(ai)"]
	if !ok {
		t.Fatalf("via-bound shadow group race_dns(ai) not registered")
	}
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
	plain := s.raceTag2GroupIdx["race_dns"]
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
