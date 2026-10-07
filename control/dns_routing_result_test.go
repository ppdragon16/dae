/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"errors"
	"net/netip"
	"testing"
)

// TestResolveUdpDnsRoutingResultTriesNormalizedKeyFirst pins the lookup order:
// the dataplane keys UDP DNS tuples with sport=0, so that must be the first
// probe; the flow's real source port is only a fallback.
func TestResolveUdpDnsRoutingResultTriesNormalizedKeyFirst(t *testing.T) {
	src := netip.MustParseAddrPort("192.168.16.129:44081")
	dst := netip.MustParseAddrPort("8.8.8.8:53")
	var asked []string
	lookup := func(s, d netip.AddrPort, out *bpfRoutingResult) error {
		asked = append(asked, s.String())
		out.Mark = 7
		return nil
	}

	result, cacheable := resolveUdpDnsRoutingResult(lookup, src, dst)
	if !cacheable {
		t.Fatal("a successful lookup must be cacheable")
	}
	if result.Mark != 7 {
		t.Fatalf("result not filled by the lookup: mark=%d", result.Mark)
	}
	if len(asked) != 1 || asked[0] != "192.168.16.129:0" {
		t.Fatalf("expected one lookup with the normalized key, got %v", asked)
	}
}

// TestResolveUdpDnsRoutingResultFallsBackToRealPort covers a dataplane that
// recorded the flow under its real source port.
func TestResolveUdpDnsRoutingResultFallsBackToRealPort(t *testing.T) {
	src := netip.MustParseAddrPort("192.168.16.129:44081")
	dst := netip.MustParseAddrPort("8.8.8.8:53")
	var asked []string
	lookup := func(s, d netip.AddrPort, out *bpfRoutingResult) error {
		asked = append(asked, s.String())
		if s.Port() == 0 {
			return errors.New("key does not exist")
		}
		out.Mark = 9
		return nil
	}

	result, cacheable := resolveUdpDnsRoutingResult(lookup, src, dst)
	if !cacheable || result.Mark != 9 {
		t.Fatalf("real-port fallback failed: cacheable=%v mark=%d", cacheable, result.Mark)
	}
	if len(asked) != 2 || asked[0] != "192.168.16.129:0" || asked[1] != "192.168.16.129:44081" {
		t.Fatalf("unexpected lookup order: %v", asked)
	}
}

// TestResolveUdpDnsRoutingResultFailsOpenOnTotalMiss pins the fix for the
// outage: when the dataplane recorded nothing for the flow, the query must not
// be dropped — a zeroed, non-cacheable result (Must == 0) keeps static/local
// DNS answers working and lets the next query re-probe the map.
func TestResolveUdpDnsRoutingResultFailsOpenOnTotalMiss(t *testing.T) {
	src := netip.MustParseAddrPort("[fdfe::c73c:bbcc:15b4:b311]:40954")
	dst := netip.MustParseAddrPort("[fdfe::1638:10ff:fe25:7177]:53")
	miss := func(s, d netip.AddrPort, out *bpfRoutingResult) error {
		return errors.New("key does not exist")
	}

	result, cacheable := resolveUdpDnsRoutingResult(miss, src, dst)
	if cacheable {
		t.Fatal("a failed lookup must not be cached: the next query has to re-probe the map")
	}
	if result == nil {
		t.Fatal("fail-open must return a usable result")
	}
	if result.Must != 0 || result.Mark != 0 || result.Outbound != 0 {
		t.Fatalf("fail-open result must be zeroed, got must=%d mark=%d outbound=%d",
			result.Must, result.Mark, result.Outbound)
	}
}
