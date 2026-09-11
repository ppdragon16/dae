/*
*  SPDX-License-Identifier: AGPL-3.0-only
*  Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

// Package trie is modified from https://github.com/openacid/succinct/blob/loc100/sskv.go.
// Slower than about 30% but more than 40% memory saving.

package trie

import (
	"fmt"
	"math/bits"
	"net/netip"
	"slices"
	"sort"

	"github.com/daeuniverse/dae/common/bitlist"
)

var ValidCidrChars = NewValidChars([]byte{'0', '1'})

type ValidChars struct {
	table    [256]byte
	n        uint16
	zeroChar byte
}

func NewValidChars(validChars []byte) (v *ValidChars) {
	v = new(ValidChars)
	for _, c := range validChars {
		if v.n == 0 {
			v.zeroChar = c
		}
		v.table[c] = byte(v.n)
		v.n++
	}
	return v
}

func (v *ValidChars) Size() int {
	return int(v.n)
}

func (v *ValidChars) IsValidChar(c byte) bool {
	return v.table[c] > 0 || c == v.zeroChar
}

// Trie is a succinct, sorted and static string set impl with compacted trie as
// storage. The space cost is about half lower than the original data.
//
// # Implementation
//
// It stores sorted strings in a compacted trie(AKA prefix tree).
// A trie node has at most 256 outgoing labels.
// A label is just a single byte.
// E.g., [ab, abc, abcd, axy, buv] is represented with a trie like the following:
// (Numbers are node id)
//
//	^ -a-> 1 -b-> 3 $
//	  |      |      `c-> 6 $
//	  |      |             `d-> 9 $
//	  |      `x-> 4 -y-> 7 $
//	  `b-> 2 -u-> 5 -v-> 8 $
//
// Internally it uses a packed []byte and a bitmap with `len([]byte)` bits to
// describe the outgoing labels of a node,:
//
//	^: ab  00
//	1: bx  00
//	2: u   0
//	3: c   0
//	4: y   0
//	5: v   0
//	6: d   0
//	7: ø
//	8: ø
//	9: ø
//
// In storage it packs labels together and bitmaps joined with separator `1`:
//
//	labels(ignore space): "ab bx u c y v d"
//	label bitmap:          0010010101010101111
//
// Finally leaf nodes are indicated by another bitmap `leaves`, in which a `1`
// at i-th bit indicates the i-th node is a leaf:
//
//	leaves: 0001001111
type Trie struct {
	leaves, labelBitmap []uint64
	ranks, selects      []int32
	labels              *bitlist.CompactBitList

	chars *ValidChars
}

// bin8[c] holds the 8-bit binary expansion of byte c, most significant bit
// first, as used by Prefix2bin128.
var bin8 [256][8]byte

func init() {
	for c := range 256 {
		for j := 0; j < 8; j++ {
			bin8[c][j] = '0' + byte(c>>(7-j)&1)
		}
	}
}

// Prefix2bin128 renders the prefix as a string of '0'/'1' bits, most
// significant bit first, exactly prefix.Bits() characters long. IPv4 prefixes
// are widened into their 4-in-6 form, so a /32 yields 128 characters.
//
// The buffer is at most 128 bytes (16 bytes x 8 bits), so it lives on the
// stack: the only heap traffic left is the returned string.
func Prefix2bin128(prefix netip.Prefix) (bin128 string) {
	n := prefix.Bits()
	if n == -1 {
		// Same message as before, but without concatenation: the argument of
		// panic(...) is re-evaluated on every iteration, so building it from
		// prefix.String() (which allocates) kept the success path non-trivial.
		panic(fmt.Sprintf("! BadPrefix: %v", prefix))
	}
	if prefix.Addr().Is4() {
		n += 96
	}
	if n == 0 {
		// A zero-bit IPv6 prefix expands to the empty string. The general path
		// below covers this too; the explicit case keeps the intent obvious.
		return ""
	}
	ip := prefix.Addr().As16()
	var buf [128]byte
	for i := range len(ip) {
		copy(buf[i*8:], bin8[ip[i]][:])
	}
	return string(buf[:n])
}

func NewTrieFromPrefixes(cidrs []netip.Prefix) (*Trie, error) {
	var keys []string
	// Convert netip.Prefix -> '0' '1' string
	for _, prefix := range cidrs {
		keys = append(keys, Prefix2bin128(prefix))
	}
	t, err := NewTrie(keys, ValidCidrChars)
	if err != nil {
		return nil, err
	}
	return t, nil
}

// NewTrie creates a new *Trie struct, from a slice of sorted strings.
func NewTrie(keys []string, chars *ValidChars) (*Trie, error) {
	// Sort and deduplicate in place. Since the keys are sorted right after,
	// deduplication is a single adjacent-element pass instead of building a
	// map (which used to allocate O(n) buckets).
	sort.Strings(keys)
	n := 0
	for _, k := range keys {
		if n == 0 || keys[n-1] != k {
			keys[n] = k
			n++
		}
	}
	keys = keys[:n]

	// Check chars.
	for _, key := range keys {
		for _, c := range []byte(key) {
			if !chars.IsValidChar(c) {
				return nil, fmt.Errorf("char out of range: %c", c)
			}
		}
	}

	if len(keys) == 0 {
		// A trie with no keys matches nothing. Build a degenerate trie
		// instead of panicking on the ranks/selects bookkeeping below.
		return &Trie{chars: chars}, nil
	}

	// Pre-compute the number of trie nodes so the allocations below can be
	// sized exactly. For sorted, deduplicated keys a plain trie has exactly
	// 1 + Σ(len(key_i) - LCP(key_i, key_{i-1})) nodes.
	numNodes := 1
	for i := range keys {
		l := len(keys[i])
		if i > 0 {
			prev := keys[i-1]
			j := 0
			for j < l && j < len(prev) && keys[i][j] == prev[j] {
				j++
			}
			l -= j
		}
		numNodes += l
	}

	ss := &Trie{
		chars:       chars,
		labels:      bitlist.NewCompactBitList(bits.Len(uint(chars.Size()))),
		leaves:      make([]uint64, 0, (numNodes+63)/64),
		labelBitmap: make([]uint64, 0, (2*numNodes+63)/64),
	}
	ss.labels.Reserve(numNodes - 1)
	lIdx := 0

	type qElt struct{ s, e, col int }

	queue := make([]qElt, 0, numNodes)
	queue = append(queue, qElt{0, len(keys), 0})

	for i := 0; i < len(queue); i++ {
		elt := queue[i]

		if elt.col == len(keys[elt.s]) {
			// a leaf node
			elt.s++
			setBit(&ss.leaves, i, 1)
		}

		for j := elt.s; j < elt.e; {

			frm := j

			for ; j < elt.e && keys[j][elt.col] == keys[frm][elt.col]; j++ {
			}

			queue = append(queue, qElt{frm, j, elt.col + 1})
			ss.labels.Append(uint64(chars.table[keys[frm][elt.col]]))
			setBit(&ss.labelBitmap, lIdx, 0)
			lIdx++
		}

		setBit(&ss.labelBitmap, lIdx, 1)
		lIdx++
	}

	ss.init()

	// Tighten.
	ss.labels.Tighten()

	leaves := make([]uint64, len(ss.leaves))
	copy(leaves, ss.leaves)
	ss.leaves = leaves

	labelBitmap := make([]uint64, len(ss.labelBitmap))
	copy(labelBitmap, ss.labelBitmap)
	ss.labelBitmap = labelBitmap

	ss.ranks = ss.ranks[:len(ss.ranks):len(ss.ranks)]
	ss.selects = ss.selects[:len(ss.selects):len(ss.selects)]

	return ss, nil
}

// HasPrefixAddr query to accept [16]byte to match IP Addr, for zero-alloc.
func (ss *Trie) HasPrefixAddr(ip [16]byte) bool {
	if len(ss.leaves) == 0 {
		// Degenerate (empty) trie: no key was stored, nothing can match.
		// HasPrefix has the same guard; without it this walks into an empty
		// slice instead of answering.
		return false
	}

	nodeId, bmIdx := 0, 0

	for i := range 128 {
		if (ss.leaves[nodeId>>6] & (1 << uint(nodeId&63))) != 0 {
			return true
		}

		bit := (ip[i>>3] >> (7 - (i & 7))) & 1

		for ; ; bmIdx++ {
			if (ss.labelBitmap[bmIdx>>6] & (1 << uint(bmIdx&63))) != 0 {
				// no more labels in this node
				return false
			}

			if byte(ss.labels.Get(bmIdx-nodeId)) == byte(bit) {
				break
			}
		}

		// go to next level
		nodeId = countZeros(ss.labelBitmap, ss.ranks, bmIdx+1)
		bmIdx = selectIthOne(ss.labelBitmap, ss.ranks, ss.selects, nodeId-1) + 1
	}

	return (ss.leaves[nodeId>>6] & (1 << uint(nodeId&63))) != 0
}

// HasPrefixAddr query to accept [6]byte to match mac address, for zero-alloc.
func (ss *Trie) HasPrefixMac(mac [6]byte) bool {
	var addr16 [16]byte
	copy(addr16[10:], mac[:])
	return ss.HasPrefixAddr(addr16)
}

// HasPrefix query for a word and return whether a prefix of the word is in the Trie.
func (ss *Trie) HasPrefix(word string) bool {
	if len(ss.leaves) == 0 {
		// Degenerate (empty) trie: no key was stored, nothing can match.
		return false
	}

	nodeId, bmIdx := 0, 0

	for i := 0; i < len(word); i++ {
		if getBit(ss.leaves, nodeId) != 0 {
			return true
		}
		c := word[i]
		if !ss.chars.IsValidChar(c) {
			return false
		}
		for ; ; bmIdx++ {
			if getBit(ss.labelBitmap, bmIdx) != 0 {
				// no more labels in this node
				return false
			}

			if byte(ss.labels.Get(bmIdx-nodeId)) == ss.chars.table[c] {
				break
			}
		}

		// go to next level

		nodeId = countZeros(ss.labelBitmap, ss.ranks, bmIdx+1)
		bmIdx = selectIthOne(ss.labelBitmap, ss.ranks, ss.selects, nodeId-1) + 1
	}

	return getBit(ss.leaves, nodeId) != 0
}

// HasSuffix iterates word backwards and checks if any suffix matches the Trie.
// The Trie must have been built with reversed strings (via ToSuffixTrieString).
func (ss *Trie) HasSuffix(word []byte) bool {
	if len(ss.leaves) == 0 {
		// Degenerate (empty) trie: no key was stored, nothing can match.
		// HasPrefix has the same guard; without it this walks into an empty
		// slice instead of answering.
		return false
	}

	// Determine label bit size.
	// We cannot access ss.labels.unitBitSize directly as it is private, but it is derived from chars.Size().
	unitBitSize := bits.Len(uint(ss.chars.Size()))

	nodeId, bmIdx := 0, 0
	labelsRaw := ss.labels.Raw()

	// Fast path for domain trie (6-bit labels) without branching inside loop
	if unitBitSize == 6 {
		for _, c := range slices.Backward(word) {
			if (ss.leaves[nodeId>>6] & (1 << uint(nodeId&63))) != 0 {
				return true
			}

			charIndex := ss.chars.table[c]
			if charIndex == 0 && c != ss.chars.zeroChar {
				return false
			}

			for ; ; bmIdx++ {
				if (ss.labelBitmap[bmIdx>>6] & (1 << uint(bmIdx&63))) != 0 {
					return false
				}

				offset := bmIdx - nodeId
				bitPos := offset * 6
				wordIdx := bitPos >> 4
				bitShift := bitPos & 15

				v := labelsRaw[wordIdx] >> bitShift
				if bitShift > 10 {
					v |= labelsRaw[wordIdx+1] << (16 - bitShift)
				}

				if byte(v&0x3F) == charIndex {
					break
				}
			}

			rankIdx := bmIdx + 1
			rankVal := int(ss.ranks[rankIdx>>6])
			bitCnt := bits.OnesCount64(ss.labelBitmap[rankIdx>>6] & ((1 << uint(rankIdx&63)) - 1))
			nodeId = rankIdx - rankVal - bitCnt
			bmIdx = selectIthOne(ss.labelBitmap, ss.ranks, ss.selects, nodeId-1) + 1
		}
		return (ss.leaves[nodeId>>6] & (1 << uint(nodeId&63))) != 0
	}

	// Generic Path
	for _, c := range slices.Backward(word) {
		if (ss.leaves[nodeId>>6] & (1 << uint(nodeId&63))) != 0 {
			return true
		}

		charIndex := ss.chars.table[c]
		if charIndex == 0 && c != ss.chars.zeroChar {
			return false
		}

		for ; ; bmIdx++ {
			if (ss.labelBitmap[bmIdx>>6] & (1 << uint(bmIdx&63))) != 0 {
				return false
			}

			if byte(ss.labels.Get(bmIdx-nodeId)) == charIndex {
				break
			}
		}

		rankIdx := bmIdx + 1
		rankVal := int(ss.ranks[rankIdx>>6])
		bitCnt := bits.OnesCount64(ss.labelBitmap[rankIdx>>6] & ((1 << uint(rankIdx&63)) - 1))
		nodeId = rankIdx - rankVal - bitCnt
		bmIdx = selectIthOne(ss.labelBitmap, ss.ranks, ss.selects, nodeId-1) + 1
	}

	return (ss.leaves[nodeId>>6] & (1 << uint(nodeId&63))) != 0
}

func setBit(bm *[]uint64, i int, v int) {
	for i>>6 >= len(*bm) {
		*bm = append(*bm, 0)
	}
	(*bm)[i>>6] |= uint64(v) << uint(i&63)
}

func getBit(bm []uint64, i int) uint64 {
	return bm[i>>6] & (1 << uint(i&63))
}

// init builds pre-calculated cache to speed up rank() and select()
func (ss *Trie) init() {
	ss.ranks = []int32{0}
	for i := 0; i < len(ss.labelBitmap); i++ {
		n := bits.OnesCount64(ss.labelBitmap[i])
		ss.ranks = append(ss.ranks, ss.ranks[len(ss.ranks)-1]+int32(n))
	}

	ss.selects = []int32{}
	n := 0
	for i := 0; i < len(ss.labelBitmap)<<6; i++ {
		z := int(ss.labelBitmap[i>>6]>>uint(i&63)) & 1
		if z == 1 && n&63 == 0 {
			ss.selects = append(ss.selects, int32(i))
		}
		n += z
	}
}

// countZeros counts the number of "0" in a bitmap before the i-th bit(excluding
// the i-th bit) on behalf of rank index.
// E.g.:
//
//	countZeros("010010", 4) == 3
//	//          012345
func countZeros(bm []uint64, ranks []int32, i int) int {
	return i - int(ranks[i>>6]) - bits.OnesCount64(bm[i>>6]&(1<<uint(i&63)-1))
}

// selectIthOne returns the index of the i-th "1" in a bitmap, on behalf of rank
// and select indexes.
// E.g.:
//
//	selectIthOne("010010", 1) == 4
//	//            012345
func selectIthOne(bm []uint64, ranks, selects []int32, i int) int {
	base := int(selects[i>>6]) & ^63
	findIthOne := i - int(ranks[base>>6])

	for i := base >> 6; i < len(bm); i++ {
		w := bm[i]
		c := bits.OnesCount64(w)
		if findIthOne < c {
			return i<<6 + select64(w, findIthOne)
		}
		findIthOne -= c
	}
	panic("no more ones")
}

// selectByte holds the popcount of a byte and the offsets of its set bits, so
// that select inside a byte is a table lookup instead of a bit-clearing loop.
type selectByte struct {
	ones int8
	pos  [8]int8
}

var selectByteTab = func() (tab [256]selectByte) {
	for v := range tab {
		e := &tab[v]
		n := 0
		for j := range 8 {
			if v>>j&1 == 1 {
				e.pos[n] = int8(j)
				n++
			}
		}
		e.ones = int8(n)
	}
	return tab
}()

// select64 returns the offset of the k-th (0-indexed) set bit in v.
// k must be less than bits.OnesCount64(v).
//
// It walks the word a byte at a time and skips any byte whose popcount is below
// k, so the O(k) bit-clearing loop this used to be is bounded by 8 iterations
// of a table lookup. That matters because selectIthOne runs once per level of a
// 128-level lookup, so k reaches the number of set bits below the cursor.
func select64(v uint64, k int) int {
	for i := 0; i < 8; i++ {
		e := &selectByteTab[byte(v)]
		c := int(e.ones)
		if k < c {
			return i<<3 + int(e.pos[k])
		}
		k -= c
		v >>= 8
	}
	// Callers contract that k < bits.OnesCount64(v); keep the old failure mode
	// (bits.TrailingZeros64(0) == 64) instead of panicking on a huge index.
	return 8 << 3
}
