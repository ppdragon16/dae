/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package trie

import (
	"math/big"
	"math/bits"
	"math/rand"
	"net/netip"
	"strings"
	"testing"
)

// TestPrefix2bin128 pins the exact bit string Prefix2bin128 produces: MSB
// first, exactly Bits() characters for IPv6, and the 4-in-6 form (so 128
// characters) for IPv4. The expectations are built independently with big.Int.
func TestPrefix2bin128(t *testing.T) {
	for _, tt := range []string{
		"1.2.3.4/32",
		"0.0.0.0/0",
		"10.0.0.0/8",
		"192.168.1.0/24",
		"::/0",
		"2001:db8::/64",
		"2001:db8:1234:5678:9abc:def0:1234:5678/128",
	} {
		p := netip.MustParsePrefix(tt)
		n := p.Bits()
		if p.Addr().Is4() {
			n += 96
		}
		b := p.Addr().As16()
		s := new(big.Int).SetBytes(b[:]).Text(2)
		if len(s) < 128 {
			s = strings.Repeat("0", 128-len(s)) + s
		}
		want := s[:n]
		if got := Prefix2bin128(p); got != want {
			t.Errorf("Prefix2bin128(%v) = %q (len %d), want %q (len %d)", p, got, len(got), want, len(want))
		}
	}
}

func TestEmptyTrieMatchesNothing(t *testing.T) {
	chars := NewValidChars([]byte("ab"))
	trie, err := NewTrie(nil, chars)
	if err != nil {
		t.Fatalf("NewTrie with no keys: %v", err)
	}
	if trie.HasPrefix("a") {
		t.Fatal("empty trie matched a prefix")
	}
	if trie.HasPrefix("") {
		t.Fatal("empty trie matched an empty word")
	}
}

func TestTrie(t *testing.T) {
	trie, err := NewTrie([]string{
		"moc.cbatnetnoc.",
		"moc.cbatnetnoc^",
		"nc.",
		"ua.moc.cbci.",
		"ua.moc.cbci^",
		"ua.moc.duolcababila.",
		"ua.moc.duolcababila^",
		"udiab.",
		"udiab^",
		"ue.cbci.",
		"ue.cbci^",
		"uhos.",
		"uhos^",
		"ul.cbci.",
		"ul.cbci^",
		"ur.dj.",
		"ur.dj^",
		"ur.llamt.",
		"ur.llamt^",
		"ur.sserpxeila.",
		"ur.sserpxeila^",
		"ur.wocsomcbci.",
		"ur.wocsomcbci^",
		"vt.32b.",
		"vt.32b^",
		"vt.akoaix.",
		"vt.akoaix^",
		"vt.eesia.",
		"vt.eesia^",
		"vt.eiq.",
		"vt.eiq^",
		"vt.gca.",
		"vt.gca^",
		"vt.ilibilib.",
		"vt.ilibilib^",
		"vt.iqnahz.",
		"vt.iqnahz^",
		"vt.ixiy.",
		"vt.ixiy^",
		"vt.low.",
		"vt.low^",
		"vt.nc361.",
		"vt.nc361^",
		"vt.obihzgnahs.",
		"vt.obihzgnahs^",
		"vt.ogmi.",
		"vt.ogmi^",
		"vt.spp.",
		"vt.spp^",
		"vt.uohsuhc.",
		"vt.uohsuhc^",
		"vt.uyuod.",
		"vt.uyuod^",
		"vt.vtig.",
		"vt.vtig^",
		"vt.vtnh.",
		"vt.vtnh^",
		"vt.zcbj.",
		"vt.zcbj^",
		"wk.moc.cbci.",
		"wk.moc.cbci^",
		"wt.moc.duolcababila.",
		"wt.moc.duolcababila^",
		"wt.moc.levarthh.",
		"wt.moc.levarthh^",
		"xc.f.",
		"xc.f^",
		"xm.moc.cbci.",
		"xm.moc.cbci^",
		"yapila.",
		"yapila^",
		"yl.lacisum.",
		"yl.lacisum^",
		"ym.moc.duolcababila.",
		"ym.moc.duolcababila^",
		"ym.pirtc.",
		"ym.pirtc^",
		"zib.anihcbmc.",
		"zib.anihcbmc^",
		"zib.duolcsndz.",
		"zib.duolcsndz^",
		"zib.fmc.",
		"zib.fmc^",
		"zk.ytamlacbci.",
		"zk.ytamlacbci^",
		"nc.ude.ctsu.srorrim.pct_.sptth_", // https://github.com/daeuniverse/daed/issues/400
	}, NewValidChars([]byte("0123456789abcdefghijklmnopqrstuvwxyz-.^_")))
	if err != nil {
		t.Fatal(err)
	}
	if !(trie.HasPrefix("nc.tset^") == true) {
		t.Fatal("^test.cn")
	}
	if !(trie.HasPrefix("nc^") == false) {
		t.Fatal("^cn")
	}
	if !(trie.HasPrefix("nc.") == true) {
		t.Fatal(".cn")
	}
	if !(trie.HasPrefix("nc.^") == true) {
		t.Fatal("^.cn")
	}
	if !(trie.HasPrefix("nc._") == true) {
		t.Fatal("_.cn")
	}
	if !(trie.HasPrefix("n") == false) {
		t.Fatal("n")
	}
	if !(trie.HasPrefix("n^") == false) {
		t.Fatal("^n")
	}
	if !(trie.HasPrefix("moc.cbatnetnoc^") == true) {
		t.Fatal("contentabc.com")
	}
}

// TestTrieHasPrefixAgainstSet builds tries of random prefixes and checks
// HasPrefix / HasPrefixAddr / HasPrefixMac against a plain map of the keys.
// The rank/select tables drive every lookup, so a bug there shows up as a
// wrong answer rather than a panic.
func TestTrieHasPrefixAgainstSet(t *testing.T) {
	r := rand.New(rand.NewSource(0xdae))
	for _, n := range []int{0, 1, 2, 7, 64, 1000} {
		keys := make(map[string]bool, n)
		for len(keys) < n {
			a := netip.AddrFrom4([4]byte{byte(r.Intn(256)), byte(r.Intn(256)), byte(r.Intn(256)), byte(r.Intn(256))})
			if r.Intn(2) == 0 {
				a = netip.AddrFrom16([16]byte{byte(r.Intn(256)), byte(r.Intn(256)), byte(r.Intn(256)), byte(r.Intn(256)), 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, byte(r.Intn(256))})
			}
			bits := 1 + r.Intn(a.BitLen())
			keys[Prefix2bin128(netip.PrefixFrom(a, bits))] = true
		}
		sorted := make([]string, 0, len(keys))
		for k := range keys {
			sorted = append(sorted, k)
		}
		tr, err := NewTrie(sorted, ValidCidrChars)
		if err != nil {
			t.Fatalf("n=%d: NewTrie: %v", n, err)
		}

		// Queries: keys themselves (must hit) and random addresses (must agree
		// with a linear scan over the keys).
		queries := make([]string, 0, 600)
		for k := range keys {
			queries = append(queries, k)
		}
		for i := 0; i < 500; i++ {
			var a netip.Addr
			if r.Intn(2) == 0 {
				a = netip.AddrFrom4([4]byte{byte(r.Intn(256)), byte(r.Intn(256)), byte(r.Intn(256)), byte(r.Intn(256))})
			} else {
				a = netip.AddrFrom16([16]byte{byte(r.Intn(256)), byte(r.Intn(256)), byte(r.Intn(256)), byte(r.Intn(256)), byte(r.Intn(256)), byte(r.Intn(256)), byte(r.Intn(256)), byte(r.Intn(256)), 0, 0, 0, 0, 0, 0, 0, 0})
			}
			queries = append(queries, Prefix2bin128(netip.PrefixFrom(netip.AddrFrom16(a.As16()), 128)))
		}

		for _, q := range queries {
			want := false
			for k := range keys {
				if strings.HasPrefix(q, k) {
					want = true
					break
				}
			}
			if got := tr.HasPrefix(q); got != want {
				t.Fatalf("n=%d HasPrefix(%q) = %v, want %v", n, q, got, want)
			}
		}

		// HasPrefixAddr must agree with the 128-bit string form.
		for i := 0; i < 500; i++ {
			a := netip.AddrFrom4([4]byte{byte(r.Intn(256)), byte(r.Intn(256)), byte(r.Intn(256)), byte(r.Intn(256))})
			key := Prefix2bin128(netip.PrefixFrom(netip.AddrFrom16(a.As16()), 128))
			if got, want := tr.HasPrefixAddr(a.As16()), tr.HasPrefix(key); got != want {
				t.Fatalf("n=%d HasPrefixAddr(%v) = %v, want %v", n, a, got, want)
			}
		}
	}
}

// TestSelect64AgainstNaive pins the byte-table select against the obvious
// bit-clearing loop it replaced.
func TestSelect64AgainstNaive(t *testing.T) {
	naive := func(v uint64, k int) int {
		for k > 0 {
			v &= v - 1
			k--
		}
		return bits.TrailingZeros64(v)
	}
	r := rand.New(rand.NewSource(0x5e1ec7))
	words := []uint64{0, 1, ^uint64(0), 1 << 63, 0x8000000000000001, 0xffffffffffffffff}
	for i := 0; i < 20000; i++ {
		words = append(words, r.Uint64(), r.Uint64()&r.Uint64(), r.Uint64()|1)
	}
	for _, v := range words {
		c := bits.OnesCount64(v)
		for k := 0; k < c; k++ {
			if got, want := select64(v, k), naive(v, k); got != want {
				t.Fatalf("select64(%#x, %d) = %d, want %d", v, k, got, want)
			}
		}
	}
}

// TestRankSelectTables checks the structure of the rank/select tables the
// lookups index into. selectIthOne tolerates a wrong selectS sample by scanning
// forward for the bit it wants, so a broken sample costs time instead of
// returning a wrong answer and a HasPrefix test cannot see it.
func TestRankSelectTables(t *testing.T) {
	r := rand.New(rand.NewSource(0x7ab1e))
	for _, n := range []int{1, 2, 7, 64, 65, 1000} {
		keys := make([]string, 0, n)
		for len(keys) < n {
			a := netip.AddrFrom4([4]byte{byte(r.Intn(256)), byte(r.Intn(256)), byte(r.Intn(256)), byte(r.Intn(256))})
			keys = append(keys, Prefix2bin128(netip.PrefixFrom(a, 8+r.Intn(25))))
		}
		tr, err := NewTrie(keys, ValidCidrChars)
		if err != nil {
			t.Fatalf("n=%d: %v", n, err)
		}
		wordNum := len(tr.labelBitmap)

		// ranks[i] is the number of set bits before word i, so it is
		// non-decreasing, starts at 0 and ends at the total popcount.
		if len(tr.ranks) != wordNum+1 {
			t.Fatalf("n=%d: len(ranks) = %d, want %d", n, len(tr.ranks), wordNum+1)
		}
		if tr.ranks[0] != 0 {
			t.Fatalf("n=%d: ranks[0] = %d, want 0", n, tr.ranks[0])
		}
		total := 0
		prev := int32(0)
		for i, v := range tr.ranks {
			if v < prev {
				t.Fatalf("n=%d: ranks[%d] = %d decreased from %d", n, i, v, prev)
			}
			prev = v
			if i > 0 {
				total += bits.OnesCount64(tr.labelBitmap[i-1])
				if int(v) != total {
					t.Fatalf("n=%d: ranks[%d] = %d, want popcount prefix %d", n, i, v, total)
				}
			}
		}

		// selects[k] is the offset of the (64k)-th set bit; it must point at a
		// set bit, and one entry must exist per group of 64 ones.
		ones := 0
		for _, w := range tr.labelBitmap {
			ones += bits.OnesCount64(w)
		}
		wantSelects := (ones + 63) / 64
		if len(tr.selects) != wantSelects {
			t.Fatalf("n=%d: len(selects) = %d, want %d", n, len(tr.selects), wantSelects)
		}
		for k, off := range tr.selects {
			i := int(off)
			if i < 0 || i>>6 >= wordNum {
				t.Fatalf("n=%d: selects[%d] = %d out of range", n, k, i)
			}
			if tr.labelBitmap[i>>6]>>uint(i&63)&1 != 1 {
				t.Fatalf("n=%d: selects[%d] = %d does not point at a set bit", n, k, i)
			}
		}
		// selects[k] must be exactly the offset of the (64k)-th set bit:
		// selectIthOne locates group k with selects[i>>6] and then adjusts by the
		// rank recorded at that offset, which only lines up for that exact bit.
		for k, off := range tr.selects {
			want, seen := 0, 0
			for w, word := range tr.labelBitmap {
				c := bits.OnesCount64(word)
				if seen+c > 64*k {
					// the (64k)-th one is inside this word
					want = w<<6 + select64(word, 64*k-seen)
					break
				}
				seen += c
			}
			if int(off) != want {
				t.Fatalf("n=%d: selects[%d] = %d, want %d (the %d-th set bit)", n, k, off, want, 64*k)
			}
			if k > 0 && tr.selects[k] <= tr.selects[k-1] {
				t.Fatalf("n=%d: selects[%d] = %d not increasing from %d", n, k, tr.selects[k], tr.selects[k-1])
			}
		}
	}
}

// TestEmptyTrieLookupMethods pins that every lookup answers false on a trie with
// no keys instead of walking into empty tables. NewTrie returns such a trie for
// an empty key list, and the DNS matchers build exactly one when a rule has no
// prefixes (the config parser rejects sip(), but the API does not).
func TestEmptyTrieLookupMethods(t *testing.T) {
	tr, err := NewTrie(nil, ValidCidrChars)
	if err != nil {
		t.Fatalf("NewTrie(nil): %v", err)
	}
	addr := netip.MustParseAddr("1.2.3.4")
	if tr.HasPrefix("") {
		t.Error("HasPrefix matched on an empty trie")
	}
	if tr.HasPrefix(Prefix2bin128(netip.PrefixFrom(addr, 32))) {
		t.Error("HasPrefix matched an address on an empty trie")
	}
	if tr.HasPrefixAddr(addr.As16()) {
		t.Error("HasPrefixAddr matched on an empty trie")
	}
	if tr.HasPrefixMac([6]byte{1, 2, 3, 4, 5, 6}) {
		t.Error("HasPrefixMac matched on an empty trie")
	}
	if tr.HasSuffix([]byte("cba.")) {
		t.Error("HasSuffix matched on an empty trie")
	}
}
