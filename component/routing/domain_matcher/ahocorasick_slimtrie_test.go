/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package domain_matcher

import (
	"math/rand"
	"strings"
	"testing"

	"github.com/daeuniverse/dae/common/consts"
	log "github.com/sirupsen/logrus"
	"golang.org/x/exp/slices"
)

func TestAhocorasickSlimtrie(t *testing.T) {

	log.SetLevel(log.TraceLevel)
	simulatedDomainSet, err := getDomain()
	if err != nil {
		t.Fatal(err)
	}
	bf := NewBruteforce(consts.MaxMatchSetLen)
	actrie := NewAhocorasickSlimtrie(consts.MaxMatchSetLen)
	for _, domains := range simulatedDomainSet {
		bf.AddSet(domains.RuleIndex, domains.Domains, domains.Key)
		actrie.AddSet(domains.RuleIndex, domains.Domains, domains.Key)
	}
	if err = bf.Build(); err != nil {
		t.Fatal(err)
	}
	if err = actrie.Build(); err != nil {
		t.Fatal(err)
	}

	rand.Seed(200)
	for i := 0; i < 10000; i++ {
		sample := TestSample[rand.Intn(len(TestSample))]
		choice := rand.Intn(10)
		switch {
		case choice < 4:
			addN := rand.Intn(5)
			buf := make([]byte, addN)
			for i := range buf {
				buf[i] = 'a' + byte(rand.Intn('z'-'a'))
			}
			sample = string(buf) + "." + sample
		case choice >= 4 && choice < 6:
			k := rand.Intn(len(sample))
			sample = sample[k:]
		default:
		}
		bitmap := bf.MatchDomainBitmap(sample)
		bitmap2 := actrie.MatchDomainBitmap(sample)
		if !slices.Equal(bitmap, bitmap2) {
			t.Fatal(i, sample, bitmap, bitmap2)
		}
	}
}

// TestAhocorasickSlimtrieCaseNormalization pins that mixed-case Full, Suffix
// and Keyword patterns match lowercased input: the matching side normalizes
// its input to lowercase and ValidDomainChars only accepts lowercase, so
// unnormalized patterns were silently dropped (Full/Suffix) or never matched
// (Keyword).
func TestAhocorasickSlimtrieCaseNormalization(t *testing.T) {
	const bitLength = 8
	actrie := NewAhocorasickSlimtrie(bitLength)
	actrie.AddSet(0, []string{"Exact.Example"}, consts.RoutingDomainKey_Full)
	actrie.AddSet(1, []string{"Example.COM"}, consts.RoutingDomainKey_Suffix)
	actrie.AddSet(2, []string{"Keyword.CASE"}, consts.RoutingDomainKey_Keyword)
	if err := actrie.Build(); err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		domain  string
		bit     uint32
		matched bool
	}{
		{"exact.example", 0, true},
		{"Exact.Example", 0, true},
		{"sub.example.com", 1, true},
		{"example.com", 1, true},
		{"xxkeyword.casexx", 2, true},
		{"exact.example.com", 0, false},
		{"notrelated.net", 1, false},
	}
	for _, c := range cases {
		bitmap := actrie.MatchDomainBitmap(c.domain)
		set := bitmap[c.bit/32]&(1<<(c.bit%32)) != 0
		if set != c.matched {
			t.Fatalf("domain %q: rule bit %d matched=%v, want %v", c.domain, c.bit, set, c.matched)
		}
	}
}

// TestAhocorasickSlimtrieRuleIndexOutOfRange pins that an out-of-range rule
// index surfaces as a Build error instead of panicking on the slice writes
// inside AddSet.
func TestAhocorasickSlimtrieRuleIndexOutOfRange(t *testing.T) {
	for _, bitIndex := range []int{-1, 2} {
		actrie := NewAhocorasickSlimtrie(2)
		actrie.AddSet(bitIndex, []string{"a.example"}, consts.RoutingDomainKey_Full)
		err := actrie.Build()
		if err == nil || !strings.Contains(err.Error(), "out of range") {
			t.Fatalf("bitIndex %d: expected out-of-range build error, got %v", bitIndex, err)
		}
	}
}
