/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package domain_matcher

import (
	"testing"

	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/component/routing"
)

// TestSizedToRuleCount verifies that a matcher sized to maxRuleIndex+1 (the new
// production behavior) produces identical bits to one sized to MaxMatchSetLen.
func TestSizedToRuleCount(t *testing.T) {
	domains := []routing.DomainSet{
		{Key: consts.RoutingDomainKey_Suffix, RuleIndex: 0, Domains: []string{"example.com"}},
		{Key: consts.RoutingDomainKey_Suffix, RuleIndex: 1, Domains: []string{"google.com"}},
		{Key: consts.RoutingDomainKey_Keyword, RuleIndex: 2, Domains: []string{"ads"}},
		{Key: consts.RoutingDomainKey_Regex, RuleIndex: 3, Domains: []string{`^www\.example\.com$`}},
	}

	bitLength := routing.MaxRuleIndex(domains) + 1 // 4
	if bitLength != 4 {
		t.Fatalf("expected bitLength 4, got %d", bitLength)
	}

	small := NewAhocorasickSlimtrie(bitLength)
	full := NewAhocorasickSlimtrie(consts.MaxMatchSetLen)
	for _, d := range domains {
		small.AddSet(d.RuleIndex, d.Domains, d.Key)
		full.AddSet(d.RuleIndex, d.Domains, d.Key)
	}
	if err := small.Build(); err != nil {
		t.Fatal(err)
	}
	if err := full.Build(); err != nil {
		t.Fatal(err)
	}

	for _, dom := range []string{
		"www.example.com", "www.google.com", "ads.example.org",
		"example.com", "google.com", "other.org", "x.example.com",
	} {
		b1 := small.MatchDomainBitmap(dom) // ceil(4/32)=1 word
		b2 := full.MatchDomainBitmap(dom)  // 32 words
		if b1[0] != b2[0] {
			t.Fatalf("domain %q: sized-to-rulecount bitmap[0]=%#x, full bitmap[0]=%#x", dom, b1[0], b2[0])
		}
	}
}
