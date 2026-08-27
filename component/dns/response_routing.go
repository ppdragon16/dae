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

type ResponseMatcherBuilder struct {
	upstreamName2Id    map[string]uint8
	simulatedDomainSet []routing.DomainSet
	ipSet              []*trie.Trie
	macSet             []*trie.Trie
	sourceIpSet        []*trie.Trie
	fallback           *routing.Outbound
	rules              []responseMatchSet
}

func NewResponseMatcherBuilder(rules []*config_parser.RoutingRule, upstreamName2Id map[string]uint8, fallback config.FunctionOrString) (b *ResponseMatcherBuilder, err error) {
	b = &ResponseMatcherBuilder{upstreamName2Id: upstreamName2Id}
	rulesBuilder := routing.NewRulesBuilder()
	rulesBuilder.RegisterFunctionParser(consts.Function_QName, routing.PlainParserFactory(b.addQName))
	rulesBuilder.RegisterFunctionParser(consts.Function_QType, TypeParserFactory(b.addQType))
	rulesBuilder.RegisterFunctionParser(consts.Function_Ip, routing.IpParserFactory(b.addIp))
	rulesBuilder.RegisterFunctionParser(consts.Function_Upstream, routing.EmptyKeyPlainParserFactory(b.addUpstream))
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

func (b *ResponseMatcherBuilder) upstreamToId(upstream string) (upstreamId consts.DnsResponseOutboundIndex, err error) {
	switch upstream {
	case consts.DnsResponseOutboundIndex_Accept.String():
		upstreamId = consts.DnsResponseOutboundIndex_Accept
	case consts.DnsResponseOutboundIndex_Reject.String():
		upstreamId = consts.DnsResponseOutboundIndex_Reject
	case consts.DnsResponseOutboundIndex_LogicalAnd.String():
		upstreamId = consts.DnsResponseOutboundIndex_LogicalAnd
	case consts.DnsResponseOutboundIndex_LogicalOr.String():
		upstreamId = consts.DnsResponseOutboundIndex_LogicalOr
	default:
		_upstreamId, ok := b.upstreamName2Id[upstream]
		if !ok {
			return 0, fmt.Errorf("upstream %v not found; please define it in \"dns.upstream\"", strconv.Quote(upstream))
		}
		upstreamId = consts.DnsResponseOutboundIndex(_upstreamId)
	}
	return upstreamId, nil
}

func (b *ResponseMatcherBuilder) addIp(f *config_parser.Function, cidrs []netip.Prefix, upstream *routing.Outbound) (err error) {
	upstreamId, err := b.upstreamToId(upstream.Name)
	if err != nil {
		return err
	}
	rule := responseMatchSet{
		Value:    uint16(len(b.ipSet)),
		Type:     consts.MatchType_IpSet,
		Not:      f.Not,
		Upstream: uint8(upstreamId),
	}
	t, err := trie.NewTrieFromPrefixes(cidrs)
	if err != nil {
		return err
	}
	b.ipSet = append(b.ipSet, t)
	b.rules = append(b.rules, rule)
	return nil
}

func (b *ResponseMatcherBuilder) addSourceMac(f *config_parser.Function, macAddrs [][6]byte, upstream *routing.Outbound) (err error) {
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
	rule := responseMatchSet{
		Value:    uint16(len(b.macSet)),
		Type:     consts.MatchType_Mac,
		Not:      f.Not,
		Upstream: uint8(upstreamId),
	}
	b.macSet = append(b.macSet, t)
	b.rules = append(b.rules, rule)
	return nil
}

func (b *ResponseMatcherBuilder) addSourceIp(f *config_parser.Function, cidrs []netip.Prefix, upstream *routing.Outbound) (err error) {
	upstreamId, err := b.upstreamToId(upstream.Name)
	if err != nil {
		return err
	}
	t, err := trie.NewTrieFromPrefixes(cidrs)
	if err != nil {
		return err
	}
	rule := responseMatchSet{
		Value:    uint16(len(b.sourceIpSet)),
		Type:     consts.MatchType_SourceIpSet,
		Not:      f.Not,
		Upstream: uint8(upstreamId),
	}
	b.sourceIpSet = append(b.sourceIpSet, t)
	b.rules = append(b.rules, rule)
	return nil
}

func (b *ResponseMatcherBuilder) addQName(f *config_parser.Function, key string, values []string, upstream *routing.Outbound) (err error) {
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
	b.rules = append(b.rules, responseMatchSet{
		Type:     consts.MatchType_DomainSet,
		Not:      f.Not,
		Upstream: uint8(upstreamId),
	})
	return nil
}

func (b *ResponseMatcherBuilder) addUpstream(f *config_parser.Function, values []string, upstream *routing.Outbound) (err error) {
	for i, value := range values {
		upstreamName := consts.OutboundLogicalOr.String()
		if i == len(values)-1 {
			upstreamName = upstream.Name
		}
		upstreamId, err := b.upstreamToId(upstreamName)
		if err != nil {
			return err
		}
		lastUpstreamId, err := b.upstreamToId(value)
		if err != nil {
			return err
		}
		b.rules = append(b.rules, responseMatchSet{
			Type:     consts.MatchType_Upstream,
			Value:    uint16(lastUpstreamId),
			Not:      f.Not,
			Upstream: uint8(upstreamId),
		})
	}
	return nil
}

func (b *ResponseMatcherBuilder) addQType(f *config_parser.Function, values []uint16, upstream *routing.Outbound) (err error) {
	for i, value := range values {
		upstreamName := consts.OutboundLogicalOr.String()
		if i == len(values)-1 {
			upstreamName = upstream.Name
		}
		upstreamId, err := b.upstreamToId(upstreamName)
		if err != nil {
			return err
		}
		b.rules = append(b.rules, responseMatchSet{
			Type:     consts.MatchType_QType,
			Value:    uint16(value),
			Not:      f.Not,
			Upstream: uint8(upstreamId),
		})
	}
	return nil
}

func (b *ResponseMatcherBuilder) addFallback(fallbackOutbound config.FunctionOrString) (err error) {
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
	b.rules = append(b.rules, responseMatchSet{
		Type:     consts.MatchType_Fallback,
		Upstream: uint8(upstreamId),
	})
	return nil
}

func (b *ResponseMatcherBuilder) Build() (matcher *ResponseMatcher, err error) {
	var m ResponseMatcher
	// Build domainMatcher, sized to the actual rule count.
	bitLength := routing.MaxRuleIndex(b.simulatedDomainSet) + 1
	if bitLength <= 0 {
		bitLength = 1
	}
	m.domainMatcher = domain_matcher.NewAhocorasickSlimtrie(bitLength)
	for _, domains := range b.simulatedDomainSet {
		m.domainMatcher.AddSet(domains.RuleIndex, domains.Domains, domains.Key)
	}
	if err = m.domainMatcher.Build(); err != nil {
		return nil, err
	}
	// IpSet.
	m.ipSet = b.ipSet
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

type ResponseMatcher struct {
	domainMatcher routing.DomainMatcher // All domain matchSets use one DomainMatcher.
	ipSet         []*trie.Trie
	macSet        []*trie.Trie
	sourceIpSet   []*trie.Trie

	matches []responseMatchSet
}

// Release frees shared interned structures held by the domain matcher.
func (m *ResponseMatcher) Release() {
	if m.domainMatcher != nil {
		m.domainMatcher.Release()
	}
}

type responseMatchSet struct {
	Value    uint16
	Not      bool
	Type     consts.MatchType
	Upstream uint8
}

func (m *ResponseMatcher) Match(
	qName string,
	qType uint16,
	ips []netip.Addr,
	upstream consts.DnsRequestOutboundIndex,
	srcMac [6]byte,
	srcIp netip.Addr,
) (upstreamIndex consts.DnsResponseOutboundIndex, err error) {
	domainMatchBitmap := common.ObtainDomainBitmap()
	defer common.RecycleDomainBitmap(domainMatchBitmap)
	if qName != "" {
		m.domainMatcher.MatchDomainBitmapInplace(qName, domainMatchBitmap)
	}
	bin128 := make([]string, 0, len(ips))
	for _, ip := range ips {
		bin128 = append(bin128, trie.Prefix2bin128(netip.PrefixFrom(netip.AddrFrom16(ip.As16()), 128)))
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
		case consts.MatchType_IpSet:
			for _, bin128 := range bin128 {
				// Check if any of IP hit the rule.
				if m.ipSet[match.Value].HasPrefix(bin128) {
					goodSubrule = true
					break
				}
			}
		case consts.MatchType_QType:
			if qType == uint16(match.Value) {
				goodSubrule = true
			}
		case consts.MatchType_Upstream:
			if upstream == consts.DnsRequestOutboundIndex(match.Value) {
				goodSubrule = true
			}
		case consts.MatchType_Mac:
			if m.macSet[match.Value].HasPrefixMac(srcMac) {
				goodSubrule = true
			}
		case consts.MatchType_SourceIpSet:
			if srcIp.IsValid() {
				srcBin128 := trie.Prefix2bin128(netip.PrefixFrom(srcIp, srcIp.BitLen()))
				if m.sourceIpSet[match.Value].HasPrefix(srcBin128) {
					goodSubrule = true
				}
			}
		case consts.MatchType_Fallback:
			goodSubrule = true
		default:
			return 0, fmt.Errorf("unknown match type: %v", match.Type)
		}
	beforeNextLoop:
		upstream := consts.DnsResponseOutboundIndex(match.Upstream)
		if upstream != consts.DnsResponseOutboundIndex_LogicalOr {
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

		if upstream&consts.DnsResponseOutboundIndex_LogicalMask !=
			consts.DnsResponseOutboundIndex_LogicalMask {
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
