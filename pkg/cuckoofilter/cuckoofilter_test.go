/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package cuckoo

import "testing"

// TestReplayFilterSemantics covers the operations vmess's replay filter uses:
// NewFilter + InsertUnique + Lookup + Reset.
func TestReplayFilterSemantics(t *testing.T) {
	f := NewFilter(1000)

	// First insert of a fingerprint must succeed.
	if !f.InsertUnique([]byte("fingerprint-1")) {
		t.Fatal("first insert should succeed")
	}
	// Duplicate insert must be rejected (replay detection).
	if f.InsertUnique([]byte("fingerprint-1")) {
		t.Fatal("duplicate insert should be rejected")
	}

	// A different fingerprint must succeed.
	if !f.InsertUnique([]byte("fingerprint-2")) {
		t.Fatal("second distinct insert should succeed")
	}

	// Lookup must find inserted items and reject unknown ones.
	if !f.Lookup([]byte("fingerprint-1")) {
		t.Fatal("lookup should find inserted item")
	}
	if f.Lookup([]byte("never-inserted")) {
		t.Fatal("lookup should not find unknown item")
	}

	if got := f.Count(); got != 2 {
		t.Fatalf("count = %d, want 2", got)
	}

	// Reset must clear the filter.
	f.Reset()
	if f.Count() != 0 {
		t.Fatalf("count after reset = %d, want 0", f.Count())
	}
	if f.Lookup([]byte("fingerprint-1")) {
		t.Fatal("lookup after reset should be empty")
	}
	if !f.InsertUnique([]byte("fingerprint-1")) {
		t.Fatal("insert after reset should succeed")
	}
}
