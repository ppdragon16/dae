/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

// Package ahocorasick implements Aho-Corasick string matching against []byte.
// It is a compact rewrite of github.com/v2rayA/ahocorasick-domain: the
// original node carried two 41-element pointer arrays (child + fails, ~656
// bytes per node). This version stores sparse children as (char, index) edges
// and the goto table as a flat []int32, cutting each node from ~704 bytes to
// ~24 bytes while preserving the exact matching semantics.
package ahocorasick

import (
	"fmt"
)

// table maps a byte to a compact alphabet index (0..N-1); invalid bytes map
// to 0.
var table = [256]byte{
	97:  0,
	98:  1,
	99:  2,
	100: 3,
	101: 4,
	102: 5,
	103: 6,
	104: 7,
	105: 8,
	106: 9,
	107: 10,
	108: 11,
	109: 12,
	110: 13,
	111: 14,
	112: 15,
	113: 16,
	114: 17,
	115: 18,
	116: 19,
	117: 20,
	118: 21,
	119: 22,
	120: 23,
	121: 24,
	122: 25,
	'-': 26,
	'.': 27,
	'^': 28,
	'$': 29,
	'1': 30,
	'2': 31,
	'3': 32,
	'4': 33,
	'5': 34,
	'6': 35,
	'7': 36,
	'8': 37,
	'9': 38,
	'0': 39,
	'_': 40,
	// Do not forget to modify N below.
}

const N = 41

// validChars is the inverse of table: alphabet index -> byte.
var validChars = [N]byte{
	'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm',
	'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z',
	'-', '.', '^', '$',
	'1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '_',
}

func IsValidChar(b byte) bool {
	return table[b] > 0 || b == 'a'
}

// edge is a single transition: input char -> child node index.
type edge struct {
	char byte
	next int32
}

// node is a compact AC state. Node 0 is the root.
type node struct {
	output   bool
	fail     int32  // fail-state index (0 = root)
	suffix   int32  // longest output-suffix index (0 = none/root)
	children []edge // sparse, no particular order
}

// Matcher is a compact Aho-Corasick automaton.
type Matcher struct {
	trie []node
	// fails is a flat dense goto table: fails[n*N + c] = the state to move to
	// from node n on char c after following the fail chain (root if none).
	fails []int32
}

// findChild returns the child index of n on char c, or -1 if none.
func (m *Matcher) findChild(n int32, c byte) int32 {
	for _, e := range m.trie[n].children {
		if e.char == c {
			return e.next
		}
	}
	return -1
}

func (m *Matcher) buildTrie(dictionary [][]byte) error {
	max := 1
	for _, blice := range dictionary {
		max += len(blice)
	}
	m.trie = make([]node, 0, max)
	m.trie = append(m.trie, node{}) // root = 0

	// Build the trie.
	for _, blice := range dictionary {
		n := int32(0)
		for _, b := range blice {
			if !IsValidChar(b) {
				return fmt.Errorf("char out of range: %c", b)
			}
			next := m.findChild(n, b)
			if next < 0 {
				next = int32(len(m.trie))
				m.trie = append(m.trie, node{})
				m.trie[n].children = append(m.trie[n].children, edge{char: b, next: next})
			}
			n = next
		}
		m.trie[n].output = true
	}

	// BFS to compute fail and suffix (output) links.
	queue := make([]int32, 0, len(m.trie))
	for _, e := range m.trie[0].children {
		m.trie[e.next].fail = 0 // root
		queue = append(queue, e.next)
	}
	for len(queue) > 0 {
		n := queue[0]
		queue = queue[1:]
		for _, e := range m.trie[n].children {
			c := e.next
			// fail(c) = goto(fail(n), e.char): walk fail chain of n until a
			// node with a child on e.char, else root.
			f := m.trie[n].fail
			for f != 0 && m.findChild(f, e.char) < 0 {
				f = m.trie[f].fail
			}
			if child := m.findChild(f, e.char); child >= 0 {
				m.trie[c].fail = child
			} else {
				m.trie[c].fail = 0
			}
			// suffix(c) = fail(c) if output else suffix(fail(c)).
			fc := m.trie[c].fail
			if m.trie[fc].output {
				m.trie[c].suffix = fc
			} else {
				m.trie[c].suffix = m.trie[fc].suffix
			}
			queue = append(queue, c)
		}
	}

	// Precompute the dense goto table.
	m.fails = make([]int32, len(m.trie)*N)
	for i := range m.trie {
		for c, ch := range validChars {
			n := int32(i)
			for n != 0 && m.findChild(n, ch) < 0 {
				n = m.trie[n].fail
			}
			m.fails[i*N+c] = n
		}
	}
	return nil
}

// NewMatcher creates a Matcher used to match against a set of blices.
func NewMatcher(dictionary [][]byte) (m *Matcher, err error) {
	m = new(Matcher)
	if err = m.buildTrie(dictionary); err != nil {
		return nil, err
	}
	return m, nil
}

// Contains returns true if any dictionary blice is a substring of in.
//
// Unlike the original v2rayA/ahocorasick-domain, bytes outside the valid
// alphabet are NOT collapsed to 'a'. The original's `child[table[b]]` lookup
// mapped any invalid byte to index 0 ('a'), which could yield a false
// positive. This version compares the actual byte and simply does not match
// on invalid bytes — consistent with Trie.HasSuffix, which also rejects them.
func (m *Matcher) Contains(in []byte) bool {
	n := int32(0)
	for _, b := range in {
		if n != 0 {
			n = m.fails[int(n)*N+int(table[b])]
		}
		if f := m.findChild(n, b); f >= 0 {
			n = f
			if m.trie[f].output {
				return true
			}
			if m.trie[f].suffix != 0 {
				return true
			}
		}
	}
	return false
}
