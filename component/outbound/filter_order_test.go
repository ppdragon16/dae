/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package outbound

import (
	"slices"
	"testing"

	"github.com/daeuniverse/dae/component/outbound/dialer"
	"github.com/daeuniverse/dae/config"
)

// TestSortedSubscriptionTagsIsDeterministic pins the helper contract the
// fixed(N) policy depends on: Go's map iteration is randomized, so the tag list
// must be sorted explicitly to be reproducible across builds and reloads.
func TestSortedSubscriptionTagsIsDeterministic(t *testing.T) {
	tagToNodeList := map[string][]string{
		"sub-b": {"node3"},
		"":      {"node0"},
		"sub-a": {"node1", "node2"},
	}
	want := []string{"", "sub-a", "sub-b"}
	for i := 0; i < 16; i++ {
		if got := sortedSubscriptionTags(tagToNodeList); !slices.Equal(got, want) {
			t.Fatalf("iteration %d: sortedSubscriptionTags = %v, want %v", i, got, want)
		}
	}
}

// TestNewDialerSetFromLinksKeepsSubscriptionOrder pins the promise example.dae
// documents for fixed(0) — "Select the first node from the group" — at the
// level users observe it: the dialer list must follow subscription-tag order,
// not Go's randomized map order, or a reload silently moves which node fixed(0)
// selects.
func TestNewDialerSetFromLinksKeepsSubscriptionOrder(t *testing.T) {
	tagToNodeList := map[string][]string{
		"sub-b": {"socks5://127.0.0.1:1081"},
		"":      {"socks5://127.0.0.1:1083"},
		"sub-a": {"socks5://127.0.0.1:1082"},
	}
	option := dialer.NewGlobalOption(&config.GlobalTrimmed{})

	for i := 0; i < 16; i++ {
		s := NewDialerSetFromLinks(option, tagToNodeList)
		got := make([]string, 0, len(s.nodeInfos))
		for _, ni := range s.nodeInfos {
			got = append(got, ni.Property.SubscriptionTag)
		}
		if want := []string{"", "sub-a", "sub-b"}; !slices.Equal(got, want) {
			t.Fatalf("iteration %d: dialer order = %v, want subscription-tag order %v", i, got, want)
		}
	}
}
