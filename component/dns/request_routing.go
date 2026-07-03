/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package dns

import (
	"fmt"
	"net/netip"
	"strconv"

	"github.com/daeuniverse/dae/common"
	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/component/routing"
	"github.com/daeuniverse/dae/component/routing/domain_matcher"
	"github.com/daeuniverse/dae/config"
	"github.com/daeuniverse/dae/pkg/config_parser"
	"github.com/daeuniverse/dae/pkg/trie"
)

type RequestMatcherBuilder struct {
	upstreamName2Id    map[string]uint8
	simulatedDomainSet []routing.DomainSet
	macSet             []*trie.Trie
	sourceIpSet        []*trie.Trie
	fallback           *routing.Outbound
	rules              []requestMatchSet
}

func NewRequestMatcherBuilder(rules []*config_parser.RoutingRule, upstreamName2Id map[string]uint8, fallback config.FunctionOrString) (b *RequestMatcherBuilder, err error) {
	b = &RequestMatcherBuilder{upstreamName2Id: upstreamName2Id}
	rulesBuilder := routing.NewRulesBuilder()
	rulesBuilder.RegisterFunctionParser(consts.Function_QName, routing.PlainParserFactory(b.addQName))
	rulesBuilder.RegisterFunctionParser(consts.Function_QType, TypeParserFactory(b.addQType))
	rulesBuilder.RegisterFunctionParser(consts.Function_Static, routing.PlainParserFactory(b.addStatic))
	rulesBuilder.RegisterFunctionParser(consts.Function_Mac, routing.MacParserFactory(b.addSourceMac))
	rulesBuilder.RegisterFunctionParser(consts.Function_SourceIp, routing.IpParserFactory(b.addSourceIp))
	if err = rulesBuilder.Apply(rules); err != nil {
		return nil, err
	}

	if err = b.addFallback(fallback); err != nil {
		return nil, err
	}

	return b, nil
}

func (b *RequestMatcherBuilder) upstreamToId(upstream string) (upstreamId consts.DnsRequestOutboundIndex, err error) {
	switch upstream {
	case consts.DnsRequestOutboundIndex_Reject.String():
		upstreamId = consts.DnsRequestOutboundIndex_Reject
	case consts.DnsRequestOutboundIndex_AsIs.String():
		upstreamId = consts.DnsRequestOutboundIndex_AsIs
	case consts.DnsRequestOutboundIndex_Static.String():
		upstreamId = consts.DnsRequestOutboundIndex_Static
	case consts.DnsRequestOutboundIndex_LogicalAnd.String():
		upstreamId = consts.DnsRequestOutboundIndex_LogicalAnd
	case consts.DnsRequestOutboundIndex_LogicalOr.String():
		upstreamId = consts.DnsRequestOutboundIndex_LogicalOr
	default:
		_upstreamId, ok := b.upstreamName2Id[upstream]
		if !ok {
			return 0, fmt.Errorf("upstream %v not found; please define it in section \"dns.upstream\"", strconv.Quote(upstream))
		}
		upstreamId = consts.DnsRequestOutboundIndex(_upstreamId)
	}
	return upstreamId, nil
}

func (b *RequestMatcherBuilder) addQName(f *config_parser.Function, key string, values []string, upstream *routing.Outbound) (err error) {
	switch consts.RoutingDomainKey(key) {
	case consts.RoutingDomainKey_Regex,
		consts.RoutingDomainKey_Full,
		consts.RoutingDomainKey_Keyword,
		consts.RoutingDomainKey_Suffix:
	default:
		return fmt.Errorf("addQName: unsupported key: %v", key)
	}
	b.simulatedDomainSet = append(b.simulatedDomainSet, routing.DomainSet{
		Key:       consts.RoutingDomainKey(key),
		RuleIndex: len(b.rules),
		Domains:   values,
	})
	upstreamId, err := b.upstreamToId(upstream.Name)
	if err != nil {
		return err
	}
	b.rules = append(b.rules, requestMatchSet{
		Type:     consts.MatchType_DomainSet,
		Not:      f.Not,
		Upstream: uint8(upstreamId),
	})
	return nil
}

func (b *RequestMatcherBuilder) addQType(f *config_parser.Function, values []uint16, upstream *routing.Outbound) (err error) {
	for i, value := range values {
		upstreamName := consts.OutboundLogicalOr.String()
		if i == len(values)-1 {
			upstreamName = upstream.Name
		}
		upstreamId, err := b.upstreamToId(upstreamName)
		if err != nil {
			return err
		}
		b.rules = append(b.rules, requestMatchSet{
			Type:     consts.MatchType_QType,
			Value:    uint16(value),
			Not:      f.Not,
			Upstream: uint8(upstreamId),
		})
	}
	return nil
}

func (b *RequestMatcherBuilder) addStatic(f *config_parser.Function, key string, values []string, upstream *routing.Outbound) (err error) {
	if len(values) != 1 {
		return fmt.Errorf("static function requires exactly one argument (static entry name)")
	}
	staticName := values[0]

	// Validate that the static entry name is provided
	if staticName == "" {
		return fmt.Errorf("static function requires a static entry name")
	}

	// Use static entry name as upstream name to find the upstream ID.
	// In dns.go New(), we create virtual upstreams for each static entry.
	upstreamId, err := b.upstreamToId(staticName)
	if err != nil {
		return err
	}
	b.rules = append(b.rules, requestMatchSet{
		Type:       consts.MatchType_Static,
		StaticName: staticName,
		Not:        f.Not,
		Upstream:   uint8(upstreamId),
	})
	return nil
}

func (b *RequestMatcherBuilder) addSourceMac(f *config_parser.Function, macAddrs [][6]byte, upstream *routing.Outbound) (err error) {
	upstreamId, err := b.upstreamToId(upstream.Name)
	if err != nil {
		return err
	}
	var addr16 [16]byte
	values := make([]netip.Prefix, 0, len(macAddrs))
	for _, mac := range macAddrs {
		copy(addr16[10:], mac[:])
		values = append(values, netip.PrefixFrom(netip.AddrFrom16(addr16), 128))
	}
	t, err := trie.NewTrieFromPrefixes(values)
	if err != nil {
		return err
	}
	rule := requestMatchSet{
		Value:    uint16(len(b.macSet)),
		Type:     consts.MatchType_Mac,
		Not:      f.Not,
		Upstream: uint8(upstreamId),
	}
	b.macSet = append(b.macSet, t)
	b.rules = append(b.rules, rule)
	return nil
}

func (b *RequestMatcherBuilder) addSourceIp(f *config_parser.Function, cidrs []netip.Prefix, upstream *routing.Outbound) (err error) {
	upstreamId, err := b.upstreamToId(upstream.Name)
	if err != nil {
		return err
	}
	t, err := trie.NewTrieFromPrefixes(cidrs)
	if err != nil {
		return err
	}
	rule := requestMatchSet{
		Value:    uint16(len(b.sourceIpSet)),
		Type:     consts.MatchType_SourceIpSet,
		Not:      f.Not,
		Upstream: uint8(upstreamId),
	}
	b.sourceIpSet = append(b.sourceIpSet, t)
	b.rules = append(b.rules, rule)
	return nil
}

func (b *RequestMatcherBuilder) addFallback(fallbackOutbound config.FunctionOrString) (err error) {
	upstream, err := routing.ParseOutbound(config.FunctionOrStringToFunction(fallbackOutbound))
	if err != nil {
		return err
	}
	if upstream.Must {
		return fmt.Errorf("unsupported param: must")
	}
	if upstream.Mark != 0 {
		return fmt.Errorf("unsupported param: mark")
	}
	upstreamId, err := b.upstreamToId(upstream.Name)
	if err != nil {
		return err
	}
	b.rules = append(b.rules, requestMatchSet{
		Type:     consts.MatchType_Fallback,
		Upstream: uint8(upstreamId),
	})
	return nil
}

func (b *RequestMatcherBuilder) Build() (matcher *RequestMatcher, err error) {
	var m RequestMatcher
	// Build domainMatcher
	m.domainMatcher = domain_matcher.NewAhocorasickSlimtrie(consts.MaxMatchSetLen)
	for _, domains := range b.simulatedDomainSet {
		m.domainMatcher.AddSet(domains.RuleIndex, domains.Domains, domains.Key)
	}
	if err = m.domainMatcher.Build(); err != nil {
		return nil, err
	}
	// MacSet and SourceIpSet.
	m.macSet = b.macSet
	m.sourceIpSet = b.sourceIpSet

	// Write routings.
	// Fallback rule MUST be the last.
	if b.rules[len(b.rules)-1].Type != consts.MatchType_Fallback {
		return nil, fmt.Errorf("fallback rule MUST be the last")
	}
	m.matches = b.rules

	return &m, nil
}

type RequestMatcher struct {
	domainMatcher routing.DomainMatcher // All domain matchSets use one DomainMatcher.
	macSet        []*trie.Trie
	sourceIpSet   []*trie.Trie

	matches []requestMatchSet
}

type requestMatchSet struct {
	Value      uint16
	Not        bool
	Type       consts.MatchType
	Upstream   uint8
	StaticName string
}

func (m *RequestMatcher) Match(
	qName string,
	qType uint16,
	srcMac [6]byte,
	srcIp netip.Addr,
) (upstreamIndex consts.DnsRequestOutboundIndex, err error) {
	domainMatchBitmap := common.ObtainDomainBitmap()
	defer common.RecycleDomainBitmap(domainMatchBitmap)
	if qName != "" {
		m.domainMatcher.MatchDomainBitmapInplace(qName, domainMatchBitmap)
	}

	goodSubrule := false
	badRule := false
	for i, match := range m.matches {
		if badRule || goodSubrule {
			goto beforeNextLoop
		}
		switch match.Type {
		case consts.MatchType_DomainSet:
			if (domainMatchBitmap[i>>5] & (1 << (uint(i) & 31))) != 0 {
				goodSubrule = true
			}
		case consts.MatchType_QType:
			if qType == match.Value {
				goodSubrule = true
			}
		case consts.MatchType_Fallback:
			goodSubrule = true
		case consts.MatchType_Static:
			// Static match always hits; the static entry name is stored in match.StaticName
			goodSubrule = true
		case consts.MatchType_Mac:
			if m.macSet[match.Value].HasPrefixMac(srcMac) {
				goodSubrule = true
			}
		case consts.MatchType_SourceIpSet:
			if srcIp.IsValid() {
				bin128 := trie.Prefix2bin128(netip.PrefixFrom(srcIp, srcIp.BitLen()))
				if m.sourceIpSet[match.Value].HasPrefix(bin128) {
					goodSubrule = true
				}
			}
		default:
			return 0, fmt.Errorf("unknown match type: %v", match.Type)
		}
	beforeNextLoop:
		upstream := consts.DnsRequestOutboundIndex(match.Upstream)
		if upstream != consts.DnsRequestOutboundIndex_LogicalOr {
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

		if upstream&consts.DnsRequestOutboundIndex_LogicalMask !=
			consts.DnsRequestOutboundIndex_LogicalMask {
			// Tail of a rule (line).
			// Decide whether to hit.
			if !badRule {
				return upstream, nil
			}
			badRule = false
		}
	}
	return 0, fmt.Errorf("no match set hit")
}
