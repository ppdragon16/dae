/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"encoding/binary"
	"fmt"

	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/component/routing"
	"github.com/daeuniverse/dae/pkg/trie"
)

type RoutingMatcher struct {
	lpmMatcher    []*trie.Trie
	domainMatcher routing.DomainMatcher // All domain matchSets use one DomainMatcher.

	matches []bpfMatchSet
}

// Match is modified from kern/tproxy.c; please keep sync.
func (m *RoutingMatcher) Match(
	sourceAddr [16]byte,
	destAddr [16]byte,
	sourcePort uint16,
	destPort uint16,
	ipVersion consts.IpVersionType,
	l4proto consts.L4ProtoType,
	domain string,
	processName [16]uint8,
	ifindex uint32,
	tos uint8,
	mac [16]byte,
) (outboundIndex consts.OutboundIndex, mark uint32, must bool, err error) {
	var bin128s [consts.MatchType_Mac + 1][16]byte
	bin128s[consts.MatchType_IpSet] = destAddr
	bin128s[consts.MatchType_SourceIpSet] = sourceAddr
	bin128s[consts.MatchType_Mac] = mac

	var domainMatchBitmap [32]uint32
	bitmapFetched := domain == ""

	goodSubrule := false
	badRule := false
	for i, match := range m.matches {
		if badRule || goodSubrule {
			goto beforeNextLoop
		}
		switch consts.MatchType(match.Type) {
		case consts.MatchType_IpSet, consts.MatchType_SourceIpSet, consts.MatchType_Mac:
			lpmIndex := uint32(binary.LittleEndian.Uint16(match.Value[:]))
			m := m.lpmMatcher[lpmIndex]
			if m.HasPrefixAddr(bin128s[match.Type]) {
				goodSubrule = true
			}
		case consts.MatchType_DomainSet:
			if !bitmapFetched {
				m.domainMatcher.MatchDomainBitmapInplace(domain, domainMatchBitmap[:])
				bitmapFetched = true
			}
			if (domainMatchBitmap[i>>5] & (1 << (uint(i) & 31))) != 0 {
				goodSubrule = true
			}
		case consts.MatchType_Port:
			portStart, portEnd := ParsePortRange(match.Value[:])
			if destPort >= portStart &&
				destPort <= portEnd {
				goodSubrule = true
			}
		case consts.MatchType_SourcePort:
			portStart, portEnd := ParsePortRange(match.Value[:])
			if sourcePort >= portStart &&
				sourcePort <= portEnd {
				goodSubrule = true
			}
		case consts.MatchType_IpVersion:
			// LittleEndian
			if ipVersion&consts.IpVersionType(match.Value[0]) > 0 {
				goodSubrule = true
			}
		case consts.MatchType_L4Proto:
			// LittleEndian
			if l4proto&consts.L4ProtoType(match.Value[0]) > 0 {
				goodSubrule = true
			}
		case consts.MatchType_ProcessName:
			if processName[0] != 0 && match.Value == processName {
				goodSubrule = true
			}
		case consts.MatchType_IfIndex:
			if ifindex == binary.LittleEndian.Uint32(match.Value[:]) {
				goodSubrule = true
			}
		case consts.MatchType_Dscp:
			if tos == match.Value[0] {
				goodSubrule = true
			}
		case consts.MatchType_Fallback:
			goodSubrule = true
		default:
			return 0, 0, false, fmt.Errorf("unknown match type: %v", match.Type)
		}
	beforeNextLoop:
		outbound := consts.OutboundIndex(match.Outbound)
		if outbound != consts.OutboundLogicalOr {
			// This match_set reaches the end of subrule.
			// We are now at end of rule, or next match_set belongs to another
			// subrule.

			if goodSubrule == match.Not {
				// This subrule does not hit.
				badRule = true
			}

			// Reset goodSubrule.
			goodSubrule = false
		}

		if outbound&consts.OutboundLogicalMask !=
			consts.OutboundLogicalMask {
			// Tail of a rule (line).
			// Decide whether to hit.
			if !badRule {
				if outbound == consts.OutboundControlPlaneRouting {
					continue
				}
				if outbound == consts.OutboundMustRules {
					must = true
					continue
				}
				if must {
					match.Must = true
				}
				return outbound, match.Mark, match.Must, nil
			}
			badRule = false
		}
	}
	return 0, 0, false, fmt.Errorf("no match set hit")
}
