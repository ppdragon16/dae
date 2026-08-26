/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"testing"
)

// TestDomainRoutingBitmapRequiresAllDomainsToMatch locks down the
// domain_routing_map invariant: bit i must be set only when EVERY cached
// domain for an IP matches rule i. An all-zero (non-matching) domain sharing
// the IP must therefore clear a bit that a single matching domain had set.
//
// This is the regression guard for the bug where googleapis.com subdomains
// (all-zero bitmap) co-residing with gemini/aistudio domains (matching the
// ai rule) on Google's shared IPv6 were incorrectly routed to the ai group.
func TestDomainRoutingBitmapRequiresAllDomainsToMatch(t *testing.T) {
	const aiRule = 3

	gemini := &[32]uint32{} // matches rule aiRule
	setBit(gemini[:], aiRule)
	play := &[32]uint32{} // matches no rule (all-zero)

	s := &domainState{}

	// Only gemini cached for this IP: ai bit must be set.
	s.add(gemini)
	_, routing := computeDomainBitmaps(s)
	if getBit(routing.Bitmap[:], aiRule) == 0 {
		t.Fatalf("gemini-only: ai bit should be set (matched==total)")
	}

	// play.googleapis.com (matches nothing) shares the same IP: ai bit must
	// be cleared because NOT all cached domains match the ai rule.
	s.add(play)
	_, routing = computeDomainBitmaps(s)
	if getBit(routing.Bitmap[:], aiRule) != 0 {
		t.Fatalf("after adding all-zero domain: ai bit must be cleared (matched<total)")
	}

	// Removing the all-zero domain restores the bit.
	s.remove(play)
	_, routing = computeDomainBitmaps(s)
	if getBit(routing.Bitmap[:], aiRule) == 0 {
		t.Fatalf("after removing all-zero domain: ai bit should be restored")
	}
}
