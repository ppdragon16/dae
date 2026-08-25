/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package domain_matcher

import (
	"fmt"
	"testing"
	"time"

	"github.com/daeuniverse/dae/common/consts"
)

// TestInternTrie verifies that two rule indexes with identical suffix lists
// share one underlying *trie.Trie, and that matching still sets the correct
// per-rule bits.
func TestInternTrie(t *testing.T) {
	actrie := NewAhocorasickSlimtrie(consts.MaxMatchSetLen)
	actrie.AddSet(0, []string{"example.com", "google.com"}, consts.RoutingDomainKey_Suffix)
	actrie.AddSet(1, []string{"example.com", "google.com"}, consts.RoutingDomainKey_Suffix)
	if err := actrie.Build(); err != nil {
		t.Fatal(err)
	}
	if actrie.trie[0] == nil || actrie.trie[1] == nil {
		t.Fatal("expected tries to be built")
	}
	if actrie.trie[0] != actrie.trie[1] {
		t.Fatalf("identical lists should share one trie, got %p vs %p", actrie.trie[0], actrie.trie[1])
	}

	bitmap := actrie.MatchDomainBitmap("www.example.com")
	if bitmap[0]&0b01 == 0 {
		t.Fatal("bit 0 should be set")
	}
	if bitmap[0]&0b10 == 0 {
		t.Fatal("bit 1 should be set")
	}
	if bitmap := actrie.MatchDomainBitmap("other.org"); bitmap[0]&0b11 != 0 {
		t.Fatal("no bits should be set for non-matching domain")
	}
}

// TestInternTrieDistinct verifies that different lists do not share a trie.
func TestInternTrieDistinct(t *testing.T) {
	actrie := NewAhocorasickSlimtrie(consts.MaxMatchSetLen)
	actrie.AddSet(0, []string{"example.com"}, consts.RoutingDomainKey_Suffix)
	actrie.AddSet(1, []string{"other.org"}, consts.RoutingDomainKey_Suffix)
	if err := actrie.Build(); err != nil {
		t.Fatal(err)
	}
	if actrie.trie[0] == actrie.trie[1] {
		t.Fatal("distinct lists must not share a trie")
	}
}

// TestInternAc verifies keyword-list interning.
func TestInternAc(t *testing.T) {
	actrie := NewAhocorasickSlimtrie(consts.MaxMatchSetLen)
	actrie.AddSet(0, []string{"ads", "tracker"}, consts.RoutingDomainKey_Keyword)
	actrie.AddSet(1, []string{"ads", "tracker"}, consts.RoutingDomainKey_Keyword)
	if err := actrie.Build(); err != nil {
		t.Fatal(err)
	}
	if actrie.ac[0] == nil || actrie.ac[1] == nil {
		t.Fatal("expected ac matchers to be built")
	}
	if actrie.ac[0] != actrie.ac[1] {
		t.Fatalf("identical keyword lists should share one matcher, got %p vs %p", actrie.ac[0], actrie.ac[1])
	}

	bitmap := actrie.MatchDomainBitmap("ads.example.com")
	if bitmap[0]&0b01 == 0 || bitmap[0]&0b10 == 0 {
		t.Fatal("both keyword bits should be set")
	}
}

// TestInternRefcountRelease verifies that releasing all matchers referencing
// a shared structure evicts it from the intern cache (no leak across reloads).
func TestInternRefcountRelease(t *testing.T) {
	internMu.Lock()
	before := len(internTries)
	internMu.Unlock()

	// Unique list so this test does not collide with other tests' entries.
	unique := []string{fmt.Sprintf("refcount-%d.example", time.Now().UnixNano())}

	a := NewAhocorasickSlimtrie(consts.MaxMatchSetLen)
	a.AddSet(0, unique, consts.RoutingDomainKey_Suffix)
	if err := a.Build(); err != nil {
		t.Fatal(err)
	}
	b := NewAhocorasickSlimtrie(consts.MaxMatchSetLen)
	b.AddSet(0, unique, consts.RoutingDomainKey_Suffix)
	if err := b.Build(); err != nil {
		t.Fatal(err)
	}
	if a.trie[0] != b.trie[0] {
		t.Fatal("expected two matchers to share one trie")
	}

	a.Release()
	b.Release()

	internMu.Lock()
	after := len(internTries)
	internMu.Unlock()
	if after != before {
		t.Fatalf("intern cache should return to size %d after releasing all refs, got %d", before, after)
	}
}

// TestInternRegexp verifies regexp interning by source.
func TestInternRegexp(t *testing.T) {
	actrie := NewAhocorasickSlimtrie(consts.MaxMatchSetLen)
	actrie.AddSet(0, []string{`^www\.google\.com$`}, consts.RoutingDomainKey_Regex)
	actrie.AddSet(1, []string{`^www\.google\.com$`}, consts.RoutingDomainKey_Regex)
	if err := actrie.Build(); err != nil {
		t.Fatal(err)
	}
	if actrie.regexp[0][0] != actrie.regexp[1][0] {
		t.Fatalf("identical regex sources should share one compiled regexp, got %p vs %p", actrie.regexp[0][0], actrie.regexp[1][0])
	}

	bitmap := actrie.MatchDomainBitmap("www.google.com")
	if bitmap[0]&0b01 == 0 || bitmap[0]&0b10 == 0 {
		t.Fatal("both regex bits should be set")
	}
}
