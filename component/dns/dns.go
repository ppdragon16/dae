/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package dns

import (
	"fmt"
	"maps"
	"net/netip"
	"net/url"
	"strings"
	"sync"

	"github.com/daeuniverse/dae/common"
	"github.com/daeuniverse/dae/common/assets"
	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/component/routing"
	"github.com/daeuniverse/dae/config"
)

var ErrBadUpstreamFormat = fmt.Errorf("bad upstream format")

type Dns struct {
	upstream         []*UpstreamResolver
	upstream2IndexMu sync.Mutex
	upstream2Index   map[*Upstream]int
	staticEntries    map[string]*config.DnsStaticEntry
	staticEntriesMu  sync.RWMutex
	reqMatcher       *RequestMatcher
	respMatcher      *ResponseMatcher
	hasResponseRules bool
	// raceGroups maps a race placeholder upstream index to its compiled group.
	// Entries are created while compiling the config; Members and the synthetic
	// Upstream are filled lazily on first use under raceMu.
	raceGroups map[uint8]*raceGroup
	raceMu     sync.RWMutex
}

// raceGroup is one compiled race group. Tag is the declared name (also the
// identity of the synthetic upstream, and the base for via-bound shadow group
// names). Specs keeps the members exactly as written - raw links or plain
// upstream tags - so a shadow group can rebuild the same "member(outbound)"
// identity the equivalent "member(via: outbound)" rule would get. Indices are
// the members' resolver indices, used for dialing and for response-rule
// matching. Members/Upstream are the lazily resolved views.
type raceGroup struct {
	Tag      string
	Specs    []string
	Indices  []uint8
	Members  []*Upstream
	Upstream *Upstream
}

// Release frees shared interned structures held by the request/response
// domain matchers. Call it when the Dns instance is discarded (e.g. DNS
// hot-swap) so interned tries can be reclaimed once unreferenced.
func (s *Dns) Release() {
	if s.reqMatcher != nil {
		s.reqMatcher.Release()
	}
	if s.respMatcher != nil {
		s.respMatcher.Release()
	}
}

type NewOption struct {
	LocationFinder          *assets.LocationFinder
	UpstreamReadyCallback   func(dnsUpstream *Upstream)
	UpstreamResolverNetwork string
}

func New(dns *config.Dns, opt *NewOption, outboundName2Id map[string]uint8) (s *Dns, err error) {
	s = &Dns{
		upstream2Index: map[*Upstream]int{
			nil: int(consts.DnsRequestOutboundIndex_AsIs),
		},
		staticEntries: make(map[string]*config.DnsStaticEntry, len(dns.Static)),
	}
	// Convert static entries to pointer map
	for k, v := range dns.Static {
		entry := v
		s.staticEntries[k] = &entry
	}
	// Collects a set of predefined upstream names for later verification.
	predefinedUpstreamNames := make(map[string]*url.URL)
	for name := range dns.Static {
		// Add static entries as virtual upstreams.
		// Each static entry becomes an upstream with scheme "static".
		u, err := url.Parse("static://" + name)
		if err != nil {
			return nil, fmt.Errorf("failed to parse static URL: %w", err)
		}
		predefinedUpstreamNames[name] = u
	}
	// Initialize upstream name to id map (it also keys race-group members).
	upstreamName2Id := map[string]uint8{}
	// Two passes: collect plain upstreams and race-group definitions first, so
	// a race group's members can reference any plain upstream regardless of
	// declaration order; then compile the groups.
	type raceGroupDef struct{ tag, link string }
	var raceGroups []raceGroupDef
	for _, upstreamRaw := range dns.Upstream {
		name, link := common.GetTagFromLinkLikePlaintext(string(upstreamRaw))
		if name == "" {
			return nil, fmt.Errorf("%w: '%v' has no tag", ErrBadUpstreamFormat, upstreamRaw)
		}
		if strings.HasPrefix(link, consts.Function_Race+"(") {
			if !strings.HasSuffix(link, ")") {
				return nil, fmt.Errorf("%w: malformed race group %q: missing ')'", ErrBadUpstreamFormat, link)
			}
			raceGroups = append(raceGroups, raceGroupDef{tag: name, link: link})
			continue
		}
		u, err := url.Parse(link)
		if err != nil {
			return nil, fmt.Errorf("%w: %v", ErrBadUpstreamFormat, err)
		}
		if _, dup := predefinedUpstreamNames[name]; dup {
			return nil, fmt.Errorf("%w: duplicate upstream tag %q", ErrBadUpstreamFormat, name)
		}
		predefinedUpstreamNames[name] = u
	}
	for _, group := range raceGroups {
		if err := s.addRaceGroup(group.tag, group.link, predefinedUpstreamNames, upstreamName2Id, opt); err != nil {
			return nil, err
		}
		dummy, err := url.Parse("race://" + group.tag)
		if err != nil {
			return nil, fmt.Errorf("failed to create race upstream URL: %w", err)
		}
		predefinedUpstreamNames[group.tag] = dummy
	}
	for _, rule := range dns.Routing.Request.Rules {
		var urlKey string
		var rawURL *url.URL
		var ok bool
		var outboundIdx uint8
		outboundIdx = 0xFF
		upstreamName := rule.Outbound.Name
		if upstreamName == consts.Function_Race {
			return nil, fmt.Errorf("race(...) in dns routing is no longer supported: define a race group in the \"upstream\" section (e.g. race_dns: 'race(udp://1.1.1.1:53,udp://8.8.8.8:53)') and route to it by tag")
		}
		var viaOutboundName string
		// Example: ... -> static(nas)
		if upstreamName == "static" {
			upstreamName = rule.Outbound.Params[0].Val
			urlKey = upstreamName
		} else if len(rule.Outbound.Params) == 1 && rule.Outbound.Params[0].Key == consts.OutboundParam_Via {
			// Virtual upstreams for outbound bindings (e.g., ... -> proxy_dns(via: sg)).
			// Check if there are params with key "via" (indicates outbound binding like proxy_dns(via: sg))
			outboundName := rule.Outbound.Params[0].Val
			// Look up outbound index
			outboundIdx, ok = outboundName2Id[outboundName]
			if !ok {
				return nil, fmt.Errorf("outbound %q not found", outboundName)
			}
			viaOutboundName = outboundName
			urlKey = upstreamName
			upstreamName = upstreamName + "(" + outboundName + ")"
		} else {
			urlKey = upstreamName
		}
		if urlKey == "asis" || urlKey == "reject" {
			continue
		}
		if baseIdx, ok := upstreamName2Id[urlKey]; ok && s.raceGroups[baseIdx] != nil {
			// Reference to a race group defined in the upstream section,
			// optionally bound to an outbound at the reference site
			// (race_dns / race_dns(via: ai)).
			if upstreamName == urlKey {
				upstreamName2Id[upstreamName] = baseIdx
				continue
			}
			shadowIdx, err := s.shadowRaceGroup(baseIdx, upstreamName, viaOutboundName, outboundIdx, predefinedUpstreamNames, upstreamName2Id, opt)
			if err != nil {
				return nil, err
			}
			upstreamName2Id[upstreamName] = shadowIdx
			continue
		}
		if rawURL, ok = predefinedUpstreamNames[urlKey]; !ok {
			return nil, fmt.Errorf("undefined upstream name in dns routing rules: %s", upstreamName)
		}
		currentUpstreamIndex := len(s.upstream)
		if currentUpstreamIndex >= int(consts.OutboundUserDefinedMax) {
			return nil, fmt.Errorf("too many upstreams")
		}
		r := &UpstreamResolver{
			Raw:     rawURL,
			Network: opt.UpstreamResolverNetwork,
			FinishInitCallback: func(i int, outbound uint8) func(raw *url.URL, upstream *Upstream) {
				return func(raw *url.URL, upstream *Upstream) {
					upstream.Outbound = consts.OutboundIndex(outbound)
					opt.UpstreamReadyCallback(upstream)
					s.upstream2IndexMu.Lock()
					s.upstream2Index[upstream] = i
					s.upstream2IndexMu.Unlock()
				}
			}(len(s.upstream), outboundIdx),
			mu:       sync.Mutex{},
			upstream: nil,
		}
		upstreamName2Id[upstreamName] = uint8(len(s.upstream))
		s.upstream = append(s.upstream, r)
	}

	// Optimize routings.
	if dns.Routing.Request.Rules, err = routing.ApplyRulesOptimizers(dns.Routing.Request.Rules,
		&routing.DatReaderOptimizer{LocationFinder: opt.LocationFinder},
		&routing.MergeAndSortRulesOptimizer{},
		&routing.DeduplicateParamsOptimizer{},
	); err != nil {
		return nil, err
	}
	if dns.Routing.Response.Rules, err = routing.ApplyRulesOptimizers(dns.Routing.Response.Rules,
		&routing.DatReaderOptimizer{LocationFinder: opt.LocationFinder},
		&routing.MergeAndSortRulesOptimizer{},
		&routing.DeduplicateParamsOptimizer{},
	); err != nil {
		return nil, err
	}

	// Parse request routing.
	reqMatcherBuilder, err := NewRequestMatcherBuilder(dns.Routing.Request.Rules, upstreamName2Id, dns.Routing.Request.Fallback)
	if err != nil {
		return nil, fmt.Errorf("failed to build DNS request routing: %w", err)
	}
	s.reqMatcher, err = reqMatcherBuilder.Build()
	if err != nil {
		return nil, fmt.Errorf("failed to build DNS request routing: %w", err)
	}
	// Parse response routing.
	s.hasResponseRules = len(dns.Routing.Response.Rules) > 0
	// Response rules may match upstream(<race tag>): expand the tag to the
	// group's member ids, because responses are attributed to the member that
	// answered. Derived here instead of stored: the groups are all compiled by
	// now (base groups in pass two, via-bound shadows while processing rules).
	raceMemberIds := make(map[string][]uint8, len(s.raceGroups))
	for _, g := range s.raceGroups {
		raceMemberIds[g.Tag] = g.Indices
	}
	respMatcherBuilder, err := NewResponseMatcherBuilder(dns.Routing.Response.Rules, upstreamName2Id, dns.Routing.Response.Fallback, raceMemberIds)
	if err != nil {
		return nil, fmt.Errorf("failed to build DNS response routing: %w", err)
	}
	s.respMatcher, err = respMatcherBuilder.Build()
	if err != nil {
		return nil, fmt.Errorf("failed to build DNS response routing: %w", err)
	}
	return s, nil
}

// addRaceGroup compiles an upstream-section race group
// (race_dns: 'race(udp://1.1.1.1:53,udp://8.8.8.8:53)'). Members may be raw
// links or the tags of other plain upstreams; nested race groups are
// rejected. The group placeholder is registered under tag so dns routing
// rules can reference the whole group by name.
func (s *Dns) addRaceGroup(tag, link string, predefined map[string]*url.URL, upstreamName2Id map[string]uint8, opt *NewOption) error {
	if idx, ok := upstreamName2Id[tag]; ok && s.raceGroups[idx] != nil {
		return fmt.Errorf("duplicate race group tag %q", tag)
	}
	body := strings.TrimSuffix(strings.TrimPrefix(link, consts.Function_Race+"("), ")")
	var specs []string
	var memberIndices []uint8
	for _, spec := range strings.Split(body, ",") {
		spec = strings.TrimSpace(spec)
		switch {
		case spec == "":
			return fmt.Errorf("race group %q requires non-empty members", tag)
		case strings.HasPrefix(spec, consts.Function_Race+"("):
			return fmt.Errorf("nested race groups are not supported (member %q of race group %q)", spec, tag)
		case !strings.Contains(spec, "://"):
			if idx, ok := upstreamName2Id[spec]; ok && s.raceGroups[idx] != nil {
				return fmt.Errorf("race group %q cannot contain another race group (member %q)", tag, spec)
			}
			if _, ok := predefined[spec]; !ok {
				return fmt.Errorf("undefined upstream %q in race group %q", spec, tag)
			}
		}
		specs = append(specs, spec)
		subIdx, exists := upstreamName2Id[spec]
		if exists {
			memberIndices = append(memberIndices, subIdx)
			continue
		}
		var raw *url.URL
		var err error
		if strings.Contains(spec, "://") {
			if raw, err = url.Parse(spec); err != nil {
				return fmt.Errorf("%w: %v", ErrBadUpstreamFormat, err)
			}
		} else {
			raw = predefined[spec]
		}
		idx := uint8(len(s.upstream))
		if int(idx) >= int(consts.OutboundUserDefinedMax) {
			return fmt.Errorf("too many upstreams")
		}
		s.upstream = append(s.upstream, &UpstreamResolver{
			Raw:     raw,
			Network: opt.UpstreamResolverNetwork,
			FinishInitCallback: func(i int, outbound uint8) func(raw *url.URL, upstream *Upstream) {
				return func(raw *url.URL, upstream *Upstream) {
					upstream.Outbound = consts.OutboundIndex(outbound)
					opt.UpstreamReadyCallback(upstream)
					s.upstream2IndexMu.Lock()
					s.upstream2Index[upstream] = i
					s.upstream2IndexMu.Unlock()
				}
			}(len(s.upstream), 0xFF),
			mu:       sync.Mutex{},
			upstream: nil,
		})
		upstreamName2Id[spec] = idx
		memberIndices = append(memberIndices, idx)
	}
	placeholder := s.registerRaceGroup(tag, specs, memberIndices, opt)
	// Pre-register under the tag so response rules can reference the group by
	// name even when no request rule does.
	upstreamName2Id[tag] = placeholder
	return nil
}

// shadowRaceGroup instantiates a via-bound copy of the race group baseTag:
// same members, each resolved through the given outbound. The shadow is
// registered under shadowName (e.g. race_dns(ai)) so repeated references
// reuse it.
func (s *Dns) shadowRaceGroup(baseIdx uint8, shadowName, outboundName string, viaOutbound uint8, predefined map[string]*url.URL, upstreamName2Id map[string]uint8, opt *NewOption) (uint8, error) {
	if idx, ok := upstreamName2Id[shadowName]; ok && s.raceGroups[idx] != nil {
		return idx, nil
	}
	base := s.raceGroups[baseIdx]
	if base == nil {
		return 0, fmt.Errorf("race group at index %d not found", baseIdx)
	}
	var memberIndices []uint8
	for _, spec := range base.Specs {
		eff := spec + "(" + outboundName + ")"
		subIdx, exists := upstreamName2Id[eff]
		if !exists {
			var raw *url.URL
			var err error
			if strings.Contains(spec, "://") {
				if raw, err = url.Parse(spec); err != nil {
					return 0, fmt.Errorf("%w: %v", ErrBadUpstreamFormat, err)
				}
			} else {
				var ok bool
				if raw, ok = predefined[spec]; !ok {
					return 0, fmt.Errorf("undefined upstream %q in race group %q", spec, base.Tag)
				}
			}
			idx := uint8(len(s.upstream))
			if int(idx) >= int(consts.OutboundUserDefinedMax) {
				return 0, fmt.Errorf("too many upstreams")
			}
			s.upstream = append(s.upstream, &UpstreamResolver{
				Raw:     raw,
				Network: opt.UpstreamResolverNetwork,
				FinishInitCallback: func(i int, outbound uint8) func(raw *url.URL, upstream *Upstream) {
					return func(raw *url.URL, upstream *Upstream) {
						upstream.Outbound = consts.OutboundIndex(outbound)
						opt.UpstreamReadyCallback(upstream)
						s.upstream2IndexMu.Lock()
						s.upstream2Index[upstream] = i
						s.upstream2IndexMu.Unlock()
					}
				}(len(s.upstream), viaOutbound),
				mu:       sync.Mutex{},
				upstream: nil,
			})
			upstreamName2Id[eff] = idx
			subIdx = idx
		}
		memberIndices = append(memberIndices, subIdx)
	}
	return s.registerRaceGroup(shadowName, base.Specs, memberIndices, opt), nil
}

// registerRaceGroup appends the group placeholder upstream and wires the
// tag/group mappings. Returns the placeholder index.
func (s *Dns) registerRaceGroup(tag string, specs []string, memberIndices []uint8, opt *NewOption) uint8 {
	placeholder := uint8(len(s.upstream))
	dummy, err := url.Parse("race://" + tag)
	if err != nil {
		dummy = &url.URL{Scheme: "race", Host: tag}
	}
	s.upstream = append(s.upstream, &UpstreamResolver{
		Raw:     dummy,
		Network: opt.UpstreamResolverNetwork,
		mu:      sync.Mutex{},
	})
	if s.raceGroups == nil {
		s.raceGroups = map[uint8]*raceGroup{}
	}
	s.raceGroups[placeholder] = &raceGroup{
		Tag:      tag,
		Specs:    specs,
		Indices:  memberIndices,
		Upstream: &Upstream{Scheme: UpstreamScheme_Race, Hostname: tag},
	}
	return placeholder
}

func (s *Dns) CheckUpstreamsFormat() error {
	for i, upstream := range s.upstream {
		// Skip race placeholder upstreams; they use a synthetic "race://" URL
		// and are never resolved directly.
		if s.raceGroups[uint8(i)] != nil {
			continue
		}
		_, _, _, _, err := ParseRawUpstream(upstream.Raw)
		if err != nil {
			return err
		}
	}
	return nil
}

func (s *Dns) GetUpstream(upstreamIndex consts.DnsRequestOutboundIndex) (upstream *Upstream, err error) {
	return s.upstreamOrRaceGroup(uint8(upstreamIndex))
}

// upstreamOrRaceGroup resolves an upstream index that may denote a race group.
// A race group yields its synthetic group upstream with Members attached - the
// placeholder resolver itself must never be resolved, its dummy "race://" URL
// has no scheme any forwarder understands.
func (s *Dns) upstreamOrRaceGroup(idx uint8) (upstream *Upstream, err error) {
	if s.raceGroups[idx] != nil {
		if upstream = s.raceGroupUpstream(idx); upstream == nil {
			return nil, fmt.Errorf("race group at index %d has no usable member", idx)
		}
		return upstream, nil
	}
	if int(idx) >= len(s.upstream) {
		return nil, fmt.Errorf("bad upstream index: %v not in [0, %v]", idx, len(s.upstream)-1)
	}
	return s.upstream[idx].GetUpstream()
}

// raceGroupMembers resolves a race group's members once and caches them.
// Returns nil when the index is not a race group or a member fails to resolve.
func (s *Dns) raceGroupMembers(idx uint8) []*Upstream {
	s.raceMu.RLock()
	g := s.raceGroups[idx]
	if g == nil {
		s.raceMu.RUnlock()
		return nil
	}
	members := g.Members
	s.raceMu.RUnlock()
	if members != nil {
		return members
	}
	// Indices are written at config load and never mutated, so they are safe to
	// read without the lock. Resolution itself can block on the network, so it
	// happens outside the lock; concurrent resolvers duplicate the work and
	// agree on the result.
	resolved := make([]*Upstream, 0, len(g.Indices))
	for _, subIdx := range g.Indices {
		up, err := s.upstream[subIdx].GetUpstream()
		if err != nil {
			return nil
		}
		resolved = append(resolved, up)
	}
	s.raceMu.Lock()
	if g.Members == nil {
		g.Members = resolved
		if g.Upstream != nil {
			g.Upstream.RaceGroup = &RaceGroup{Tag: g.Tag, Members: resolved}
		}
	}
	s.raceMu.Unlock()
	return resolved
}

// raceGroupUpstream returns the synthetic group upstream for a race placeholder
// index, with its members attached, or nil when the index is not a race group
// or its members cannot be resolved.
func (s *Dns) raceGroupUpstream(idx uint8) *Upstream {
	s.raceMu.RLock()
	g := s.raceGroups[idx]
	if g == nil || g.Upstream == nil {
		s.raceMu.RUnlock()
		return nil
	}
	up, ready := g.Upstream, g.Members != nil
	s.raceMu.RUnlock()
	if ready {
		return up
	}
	if len(s.raceGroupMembers(idx)) == 0 {
		return nil
	}
	return up
}

// GetRaceUpstreams returns the resolved member upstreams of a race group,
// resolving them lazily on first call. Returns nil if this index is not a race
// group.
func (s *Dns) GetRaceUpstreams(upstreamIndex consts.DnsRequestOutboundIndex) []*Upstream {
	return s.raceGroupMembers(uint8(upstreamIndex))
}

func (s *Dns) HasResponseRules() bool {
	return s.hasResponseRules
}

func (s *Dns) UpdateStaticEntry(name string, entry *config.DnsStaticEntry) error {
	s.staticEntriesMu.Lock()
	defer s.staticEntriesMu.Unlock()
	if oldEntry, ok := s.staticEntries[name]; ok {
		// If new TTL is 0, keep the old TTL
		if entry.TTL == 0 {
			entry.TTL = oldEntry.TTL
		}
		s.staticEntries[name] = entry
		return nil
	}
	return fmt.Errorf("the entry '%s' doesn't exist", name)
}

func (s *Dns) GetStaticEntries() map[string]*config.DnsStaticEntry {
	s.staticEntriesMu.RLock()
	defer s.staticEntriesMu.RUnlock()
	// Return a copy to avoid race conditions
	result := make(map[string]*config.DnsStaticEntry, len(s.staticEntries))
	maps.Copy(result, s.staticEntries)
	return result
}

func (s *Dns) GetStaticEntry(name string) (*config.DnsStaticEntry, bool) {
	s.staticEntriesMu.RLock()
	defer s.staticEntriesMu.RUnlock()
	entry, ok := s.staticEntries[name]
	return entry, ok
}

func (s *Dns) RequestSelect(qname string, qtype uint16, srcMac [6]byte, srcIp netip.Addr) (upstreamIndex consts.DnsRequestOutboundIndex, err error) {
	// Route.
	upstreamIndex, err = s.reqMatcher.Match(qname, qtype, srcMac, srcIp)
	if err != nil {
		return 0, err
	}
	// nil indicates AsIs.
	if upstreamIndex == consts.DnsRequestOutboundIndex_AsIs ||
		upstreamIndex == consts.DnsRequestOutboundIndex_Reject {
		return upstreamIndex, nil
	}
	if int(upstreamIndex) >= len(s.upstream) {
		return 0, fmt.Errorf("bad upstream index: %v not in [0, %v]", upstreamIndex, len(s.upstream)-1)
	}
	return upstreamIndex, nil
}

// HasClientRequestRules returns whether the request routing uses client-specific matchers (mac or sip).
func (s *Dns) HasClientRequestRules() bool {
	return len(s.reqMatcher.macSet) > 0 || len(s.reqMatcher.sourceIpSet) > 0
}

func (s *Dns) ResponseSelect(qname string, qtype uint16, ips []netip.Addr, rcode uint16, fromUpstream *Upstream, srcMac [6]byte, srcIp netip.Addr) (upstreamIndex consts.DnsResponseOutboundIndex, upstream *Upstream, err error) {
	// Prepare routing.
	s.upstream2IndexMu.Lock()
	from := s.upstream2Index[fromUpstream]
	s.upstream2IndexMu.Unlock()
	// Route.
	upstreamIndex, err = s.respMatcher.Match(qname, qtype, ips, consts.DnsRequestOutboundIndex(from), srcMac, srcIp, rcode)
	if err != nil {
		return 0, nil, err
	}
	// Get corresponding upstream if upstream is neither 'accept' nor 'reject'.
	if !upstreamIndex.IsReserved() {
		if int(upstreamIndex) >= len(s.upstream) {
			return 0, nil, fmt.Errorf("bad upstream index: %v not in [0, %v]", upstreamIndex, len(s.upstream)-1)
		}
		// Resolves a race-group target into its synthetic group upstream with
		// Members attached, so callers can expand it without special cases.
		upstream, err = s.upstreamOrRaceGroup(uint8(upstreamIndex))
		if err != nil {
			return 0, nil, err
		}
	} else {
		// Assign explicitly to let coder know.
		upstream = nil
	}
	return upstreamIndex, upstream, nil
}
