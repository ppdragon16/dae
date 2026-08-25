/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package ahocorasick

import (
	"math/rand"
	"strings"
	"testing"
)

// bruteContains reports whether any keyword is a substring of in.
func bruteContains(keywords [][]byte, in []byte) bool {
	for _, k := range keywords {
		if strings.Contains(string(in), string(k)) {
			return true
		}
	}
	return false
}

func TestContainsMatchesBruteForce(t *testing.T) {
	rand.Seed(200)
	const valid = "abcdefghijklmnopqrstuvwxyz-.^$0123456789_"

	randKeyword := func() []byte {
		l := 1 + rand.Intn(12)
		b := make([]byte, l)
		for i := range b {
			b[i] = valid[rand.Intn(len(valid))]
		}
		return b
	}

	for round := 0; round < 200; round++ {
		n := 1 + rand.Intn(30)
		keywords := make([][]byte, n)
		for i := range keywords {
			keywords[i] = randKeyword()
		}
		m, err := NewMatcher(keywords)
		if err != nil {
			t.Fatal(err)
		}
		for trial := 0; trial < 1000; trial++ {
			l := rand.Intn(40)
			in := make([]byte, l)
			for i := range in {
				in[i] = valid[rand.Intn(len(valid))]
			}
			got := m.Contains(in)
			want := bruteContains(keywords, in)
			if got != want {
				t.Fatalf("round %d: Contains(%q) = %v, want %v (keywords=%q)",
					round, in, got, want, keywords)
			}
		}
	}
}

func TestContainsBasic(t *testing.T) {
	cases := []struct {
		keywords []string
		in       string
		want     bool
	}{
		{[]string{"ads"}, "^www.example.com$", false},
		{[]string{"ads"}, "^ads.example.com$", true},
		{[]string{"example", "google"}, "^www.google.com$", true},
		{[]string{"ab", "bc"}, "^abc$", true},
		{[]string{"abc", "bcd"}, "^abcd$", true},
		// suffix-link: "bc" is a keyword, "abc" is a keyword too.
		{[]string{"abc", "bc"}, "^abc$", true},
		{[]string{"xyz"}, "^abc$", false},
	}
	for _, c := range cases {
		var dict [][]byte
		for _, k := range c.keywords {
			dict = append(dict, []byte(k))
		}
		m, err := NewMatcher(dict)
		if err != nil {
			t.Fatal(err)
		}
		if got := m.Contains([]byte(c.in)); got != c.want {
			t.Errorf("Contains(%q) = %v, want %v (keywords=%v)", c.in, got, c.want, c.keywords)
		}
	}
}
