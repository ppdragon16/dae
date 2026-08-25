/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package domain_matcher

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"sync"

	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/pkg/trie"
	"github.com/daeuniverse/outbound/pool"
	log "github.com/sirupsen/logrus"
	"github.com/v2rayA/ahocorasick-domain"
)

var ValidDomainChars = trie.NewValidChars([]byte("0123456789abcdefghijklmnopqrstuvwxyz-.^_"))

var bitmapPool = sync.Pool{
	New: func() any {
		return make([]uint32, 128)
	},
}

// Intern caches for content-addressed matcher structures. The routing,
// DNS-request and DNS-response matchers are built independently but commonly
// reference the same domain lists (e.g. geosite:cn referenced from several
// sections). Interning lets identical lists share one underlying
// trie / AC-automaton / compiled-regexp, cutting resident memory roughly by
// the overlap factor. The built structures are immutable after construction,
// so sharing them across rule indexes is safe.
//
// Keys are SHA-256 content hashes rather than the raw pattern strings: a
// large list such as geosite:cn runs into the multi-MB range as raw strings,
// which would dominate the cache entry it describes (the succinct trie itself
// is only ~800 KB). SHA-256 collisions are treated as impossible at this
// scale (~2^-128 birthday bound).
type trieInternEntry struct {
	trie *trie.Trie
	refs int
}
type acInternEntry struct {
	matcher *ahocorasick.Matcher
	refs    int
}
type regexpInternEntry struct {
	re   *regexp.Regexp
	refs int
}

// Intern entries are reference-counted: refs = number of live (matcher, rule)
// references. AhocorasickSlimtrie.Release() decrements on hot-swap so a shared
// structure is reclaimed from the cache once no matcher references it (no
// unbounded growth across reloads).
var (
	internMu     sync.Mutex
	internTries  = make(map[[32]byte]*trieInternEntry)
	internAcs    = make(map[[32]byte]*acInternEntry)
	internRegexp = make(map[string]*regexpInternEntry)
)

// hashStrings returns a canonical content hash for a sorted list of strings.
// The caller must sort strs first so the hash is order-independent.
func hashStrings(strs []string) [32]byte {
	h := sha256.New()
	for _, s := range strs {
		h.Write([]byte(s))
		h.Write([]byte{0}) // separator: domain strings never contain NUL
	}
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

// hashBytes is the [][]byte analogue of hashStrings.
func hashBytes(strs [][]byte) [32]byte {
	h := sha256.New()
	for _, s := range strs {
		h.Write(s)
		h.Write([]byte{0})
	}
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

// internTrie returns a shared *trie.Trie for the given (already "$"-trimmed
// and reversed) pattern list. It sorts the list in place to obtain a
// canonical, order-independent hash key; trie.NewTrie sorts again internally,
// which is a no-op on already-sorted input. created reports whether this was
// the first build of that content.
func internTrie(patterns []string) (t *trie.Trie, key [32]byte, created bool, err error) {
	sort.Strings(patterns)
	key = hashStrings(patterns)
	internMu.Lock()
	defer internMu.Unlock()
	if e, ok := internTries[key]; ok {
		e.refs++
		return e.trie, key, false, nil
	}
	t, err = trie.NewTrie(patterns, ValidDomainChars)
	if err != nil {
		return nil, key, false, err
	}
	internTries[key] = &trieInternEntry{trie: t, refs: 1}
	return t, key, true, nil
}

// internAc returns a shared *ahocorasick.Matcher for the given keyword list.
// Unlike trie.NewTrie, ahocorasick.NewMatcher does not canonicalize input
// order, so we sort a copy to obtain both a stable key and a stable build.
func internAc(patterns [][]byte) (m *ahocorasick.Matcher, key [32]byte, created bool, err error) {
	sorted := make([][]byte, len(patterns))
	copy(sorted, patterns)
	sort.Slice(sorted, func(i, j int) bool { return bytes.Compare(sorted[i], sorted[j]) < 0 })
	key = hashBytes(sorted)
	internMu.Lock()
	defer internMu.Unlock()
	if e, ok := internAcs[key]; ok {
		e.refs++
		return e.matcher, key, false, nil
	}
	m, err = ahocorasick.NewMatcher(sorted)
	if err != nil {
		return nil, key, false, err
	}
	internAcs[key] = &acInternEntry{matcher: m, refs: 1}
	return m, key, true, nil
}

// compileInternedRegexp compiles src, returning a shared *regexp.Regexp.
// regexp.Regexp is immutable and safe for concurrent use.
func compileInternedRegexp(src string) (*regexp.Regexp, error) {
	internMu.Lock()
	defer internMu.Unlock()
	if e, ok := internRegexp[src]; ok {
		e.refs++
		return e.re, nil
	}
	r, err := regexp.Compile(src)
	if err != nil {
		return nil, err
	}
	internRegexp[src] = &regexpInternEntry{re: r, refs: 1}
	return r, nil
}

func releaseTrieKeys(keys [][32]byte) {
	internMu.Lock()
	defer internMu.Unlock()
	for _, k := range keys {
		if e, ok := internTries[k]; ok {
			e.refs--
			if e.refs <= 0 {
				delete(internTries, k)
			}
		}
	}
}

func releaseAcKeys(keys [][32]byte) {
	internMu.Lock()
	defer internMu.Unlock()
	for _, k := range keys {
		if e, ok := internAcs[k]; ok {
			e.refs--
			if e.refs <= 0 {
				delete(internAcs, k)
			}
		}
	}
}

func releaseRegexpSources(sources []string) {
	internMu.Lock()
	defer internMu.Unlock()
	for _, src := range sources {
		if e, ok := internRegexp[src]; ok {
			e.refs--
			if e.refs <= 0 {
				delete(internRegexp, src)
			}
		}
	}
}

type AhocorasickSlimtrie struct {
	validAcIndexes     []int
	validTrieIndexes   []int
	validRegexpIndexes []int
	ac                 []*ahocorasick.Matcher
	trie               []*trie.Trie
	regexp             [][]*regexp.Regexp

	toBuildAc   [][][]byte
	toBuildTrie [][]string
	err         error

	// Intern keys referenced by this matcher (with multiplicity), for
	// releasing refcounts when the matcher is discarded on reload.
	trieInternKeys [][32]byte
	acInternKeys   [][32]byte
	regexpSources  []string
}

func NewAhocorasickSlimtrie(bitLength int) *AhocorasickSlimtrie {
	return &AhocorasickSlimtrie{
		ac:          make([]*ahocorasick.Matcher, bitLength),
		trie:        make([]*trie.Trie, bitLength),
		regexp:      make([][]*regexp.Regexp, bitLength),
		toBuildAc:   make([][][]byte, bitLength),
		toBuildTrie: make([][]string, bitLength),
	}
}
func (n *AhocorasickSlimtrie) AddSet(bitIndex int, patterns []string, typ consts.RoutingDomainKey) {
	if n.err != nil {
		return
	}
	// Pre-size the target slice to avoid repeated reallocation across the
	// pattern loop below. Suffix domains expand to at most two trie patterns.
	switch typ {
	case consts.RoutingDomainKey_Full:
		n.toBuildTrie[bitIndex] = growSlice(n.toBuildTrie[bitIndex], len(patterns))
	case consts.RoutingDomainKey_Suffix:
		n.toBuildTrie[bitIndex] = growSlice(n.toBuildTrie[bitIndex], 2*len(patterns))
	case consts.RoutingDomainKey_Keyword:
		n.toBuildAc[bitIndex] = growSlice(n.toBuildAc[bitIndex], len(patterns))
	case consts.RoutingDomainKey_Regex:
		n.regexp[bitIndex] = growSlice(n.regexp[bitIndex], len(patterns))
	}
nextPattern:
	for _, d := range patterns {
		switch typ {
		case consts.RoutingDomainKey_Full:
			for _, r := range []byte(d) {
				if !ValidDomainChars.IsValidChar(r) {
					log.Warnf("DomainMatcher: skip bad full domain: %v: unexpected char: %v", d, string(r))
					continue nextPattern
				}
			}
			n.toBuildTrie[bitIndex] = append(n.toBuildTrie[bitIndex], "^"+d+"$")
		case consts.RoutingDomainKey_Suffix:
			for _, r := range []byte(d) {
				if !ValidDomainChars.IsValidChar(r) {
					log.Warnf("DomainMatcher: skip bad suffix domain: %v: unexpected char: %v", d, string(r))
					continue nextPattern
				}
			}
			if strings.HasPrefix(d, ".") {
				// abc.example.com
				n.toBuildTrie[bitIndex] = append(n.toBuildTrie[bitIndex], d+"$")
				// cannot match example.com
			} else {
				// xxx.example.com
				n.toBuildTrie[bitIndex] = append(n.toBuildTrie[bitIndex], "."+d+"$")
				// example.com
				n.toBuildTrie[bitIndex] = append(n.toBuildTrie[bitIndex], "^"+d+"$")
				// cannot match abcexample.com
			}
		case consts.RoutingDomainKey_Keyword:
			// Only use ac automaton for "keyword" matching to save memory.
			n.toBuildAc[bitIndex] = append(n.toBuildAc[bitIndex], []byte(d))
		case consts.RoutingDomainKey_Regex:
			r, err := compileInternedRegexp(d)
			if err != nil {
				n.err = fmt.Errorf("failed to compile regex: %v", d)
				return
			}
			n.regexp[bitIndex] = append(n.regexp[bitIndex], r)
			n.regexpSources = append(n.regexpSources, d)
		default:
			n.err = fmt.Errorf("unknown RoutingDomainKey: %v", typ)
			return
		}
	}
}
func (n *AhocorasickSlimtrie) MatchDomainBitmap(domain string) (bitmap []uint32) {
	N := len(n.ac) / 32
	if len(n.ac)%32 != 0 {
		N++
	}
	bitmapPtr := bitmapPool.Get().([]uint32)
	if cap(bitmapPtr) < N {
		bitmapPtr = make([]uint32, N)
	}
	bitmap = bitmapPtr[:N]
	for i := range bitmap {
		bitmap[i] = 0
	}

	n.MatchDomainBitmapInplace(domain, bitmap)
	return bitmap
}
func (n *AhocorasickSlimtrie) MatchDomainBitmapInplace(domain string, bitmap []uint32) {
	N := len(n.ac) / 32
	if len(n.ac)%32 != 0 {
		N++
	}
	if len(bitmap) < N {
		return
	}
	for i := range bitmap {
		bitmap[i] = 0
	}

	buf := pool.GetBuffer(256)
	defer pool.PutBuffer(buf)
	dLen := len(domain)
	if dLen == 0 || dLen > 253 {
		return
	}

	// Faster byte level: strings.ToLower(strings.TrimSuffix(domain, "."))
	if domain[dLen-1] == '.' {
		dLen--
	}
	acDomainBytes := buf[:dLen+2] // ^domain$
	acDomainBytes[0] = '^'
	for i := 0; i < dLen; i++ {
		c := domain[i]
		if c >= 'A' && c <= 'Z' {
			c += 'a' - 'A'
		}
		acDomainBytes[i+1] = c
	}
	acDomainBytes[dLen+1] = '$'

	// Domain should consist of 'a'-'z' and '.' and '-'
	// NOTE: DO NOT VERIFY THE DOMAIN TO MATCH: https://github.com/daeuniverse/dae/issues/528
	// for _, b := range []byte(domain) {
	// 	if !ahocorasick.IsValidChar(b) {
	// 		return bitmap
	// 	}
	// }
	// Suffix matching via backward iteration (avoids string reversal allocation).
	checkDomain := acDomainBytes[:dLen+1] // ^domain
	for _, i := range n.validTrieIndexes {
		idx, bit := i>>5, uint(i)&31
		if bitmap[idx]&(1<<bit) != 0 {
			continue
		}
		if n.trie[i].HasSuffix(checkDomain) {
			bitmap[idx] |= 1 << bit
		}
	}
	// Keyword matching.
	// Add magic chars as head and tail.
	for _, i := range n.validAcIndexes {
		idx, bit := i>>5, uint(i)&31
		if bitmap[idx]&(1<<bit) != 0 {
			continue
		}
		if n.ac[i].Contains(acDomainBytes) {
			bitmap[idx] |= 1 << bit
		}
	}
	// Regex matching.
	domainBytes := acDomainBytes[1 : dLen+1] // domain
	for _, i := range n.validRegexpIndexes {
		idx, bit := i>>5, uint(i)&31
		if bitmap[idx]&(1<<bit) != 0 {
			continue
		}
		for _, r := range n.regexp[i] {
			if r.Match(domainBytes) {
				bitmap[idx] |= 1 << bit
				break
			}
		}
	}
}

// ReleaseBitmap returns the bitmap to the pool.
func ReleaseBitmap(bitmap []uint32) {
	if bitmap == nil {
		return
	}
	// Only pool buffers with the exact expected capacity (128) to avoid
	// large buffer pollution. Oversized buffers are left for GC.
	if cap(bitmap) == 128 {
		bitmapPool.Put(bitmap[:128])
	}
}
func ToSuffixTrieString(s string) string {
	// No need for end char "$".
	b := []byte(strings.TrimSuffix(s, "$"))
	// Reverse.
	half := len(b) / 2
	for i := 0; i < half; i++ {
		b[i], b[len(b)-i-1] = b[len(b)-i-1], b[i]
	}
	return string(b)
}
func ToSuffixTrieStrings(s []string) []string {
	to := make([]string, len(s))
	for i := range s {
		to[i] = ToSuffixTrieString(s[i])
	}
	return to
}
func (n *AhocorasickSlimtrie) Build() (err error) {
	if n.err != nil {
		return n.err
	}
	n.validAcIndexes = make([]int, 0, len(n.toBuildAc)/8)
	n.validTrieIndexes = make([]int, 0, len(n.toBuildAc)/8)
	n.validRegexpIndexes = make([]int, 0, len(n.toBuildAc)/8)

	// Intern stats: "built" counts structures created in this Build, "reused"
	// counts structures shared from an earlier matcher build (dedup savings).
	var acBuilt, acReused, trieBuilt, trieReused int

	// Build AC automaton.
	for i, toBuild := range n.toBuildAc {
		if len(toBuild) == 0 {
			continue
		}
		var created bool
		var key [32]byte
		n.ac[i], key, created, err = internAc(toBuild)
		if err != nil {
			return err
		}
		n.acInternKeys = append(n.acInternKeys, key)
		if created {
			acBuilt++
		} else {
			acReused++
		}
		n.validAcIndexes = append(n.validAcIndexes, i)
	}

	// Build succinct trie.
	for i, toBuild := range n.toBuildTrie {
		if len(toBuild) == 0 {
			continue
		}
		toBuild = ToSuffixTrieStrings(toBuild)
		var created bool
		var key [32]byte
		n.trie[i], key, created, err = internTrie(toBuild)
		if err != nil {
			return err
		}
		n.trieInternKeys = append(n.trieInternKeys, key)
		if created {
			trieBuilt++
		} else {
			trieReused++
		}
		n.validTrieIndexes = append(n.validTrieIndexes, i)
	}

	// Regexp.
	for i := range n.regexp {
		if len(n.regexp[i]) == 0 {
			continue
		}
		n.validRegexpIndexes = append(n.validRegexpIndexes, i)
	}

	// Release unused data.
	n.toBuildAc = nil
	n.toBuildTrie = nil

	log.Infof("domain matcher intern: ac=%d built/%d reused, trie=%d built/%d reused, regexp=%d rules",
		acBuilt, acReused, trieBuilt, trieReused, len(n.validRegexpIndexes))
	return nil
}

// Release decrements the intern-cache refcounts held by this matcher. Call it
// when the matcher is discarded (e.g. hot-swap on routing/DNS update) so the
// shared tries/AC-automata/regexps it referenced can be reclaimed from the
// cache once no matcher references them anymore.
func (n *AhocorasickSlimtrie) Release() {
	releaseTrieKeys(n.trieInternKeys)
	releaseAcKeys(n.acInternKeys)
	releaseRegexpSources(n.regexpSources)
	n.trieInternKeys = nil
	n.acInternKeys = nil
	n.regexpSources = nil
}

// growSlice ensures s has room for at least extra more elements, reallocating
// and copying at most once when necessary, and returns the grown slice.
func growSlice[T any](s []T, extra int) []T {
	if cap(s)-len(s) >= extra {
		return s
	}
	grown := make([]T, len(s), len(s)+extra)
	copy(grown, s)
	return grown
}
