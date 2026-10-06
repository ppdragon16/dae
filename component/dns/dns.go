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
	// raceGroupIndices maps from a race placeholder upstream index to its sub-upstream indices.
	raceGroupIndices map[uint8][]uint8
	// raceUpstreams caches resolved sub-upstreams, populated lazily on first use.
	raceUpstreams map[uint8][]*Upstream
	raceCacheMu   sync.RWMutex
	// raceTag2GroupIdx maps an upstream-section race group tag ("race_dns") to
	// its placeholder upstream index.
	raceTag2GroupIdx map[string]uint8
	// raceTag2Members maps a race group tag to its member specs (raw links or
	// plain upstream tags), kept so via-bound shadow groups can be built.
	raceTag2Members map[string][]string
	// raceTag2MemberIds maps a race group tag (base or via-bound shadow) to its
	// members' upstream indices, so response rules can expand upstream(<tag>)
	// into "answered by any member".
	raceTag2MemberIds map[string][]uint8
	// raceGroupUpstreams holds the synthetic group upstream per placeholder
	// index. Members are filled lazily on first use.
	raceGroupUpstreams map[uint8]*Upstream
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
		if groupIdx, ok := s.raceTag2GroupIdx[urlKey]; ok {
			// Reference to a race group defined in the upstream section,
			// optionally bound to an outbound at the reference site
			// (race_dns / race_dns(via: ai)).
			if upstreamName == urlKey {
				upstreamName2Id[upstreamName] = groupIdx
				continue
			}
			groupIdx, err = s.shadowRaceGroup(urlKey, upstreamName, viaOutboundName, outboundIdx, predefinedUpstreamNames, upstreamName2Id, opt)
			if err != nil {
				return nil, err
			}
			upstreamName2Id[upstreamName] = groupIdx
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
	respMatcherBuilder, err := NewResponseMatcherBuilder(dns.Routing.Response.Rules, upstreamName2Id, dns.Routing.Response.Fallback, s.raceTag2MemberIds)
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
			if _, ok := predefined[spec]; !ok {
				return fmt.Errorf("undefined upstream %q in race group %q", spec, tag)
			}
			if _, isGroup := s.raceTag2GroupIdx[spec]; isGroup {
				return fmt.Errorf("race group %q cannot contain another race group (member %q)", tag, spec)
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
	if s.raceTag2Members == nil {
		s.raceTag2Members = map[string][]string{}
	}
	s.raceTag2Members[tag] = specs
	if s.raceTag2MemberIds == nil {
		s.raceTag2MemberIds = map[string][]uint8{}
	}
	s.raceTag2MemberIds[tag] = memberIndices
	placeholder := s.registerRaceGroup(tag, memberIndices, opt)
	// Pre-register under the tag so response rules can reference the group by
	// name even when no request rule does.
	upstreamName2Id[tag] = placeholder
	return nil
}

// shadowRaceGroup instantiates a via-bound copy of the race group baseTag:
// same members, each resolved through the given outbound. The shadow is
// registered under shadowName (e.g. race_dns(ai)) so repeated references
// reuse it.
func (s *Dns) shadowRaceGroup(baseTag, shadowName, outboundName string, viaOutbound uint8, predefined map[string]*url.URL, upstreamName2Id map[string]uint8, opt *NewOption) (uint8, error) {
	if idx, ok := s.raceTag2GroupIdx[shadowName]; ok {
		return idx, nil
	}
	var memberIndices []uint8
	for _, spec := range s.raceTag2Members[baseTag] {
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
					return 0, fmt.Errorf("undefined upstream %q in race group %q", spec, baseTag)
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
	if s.raceTag2MemberIds == nil {
		s.raceTag2MemberIds = map[string][]uint8{}
	}
	s.raceTag2MemberIds[shadowName] = memberIndices
	return s.registerRaceGroup(shadowName, memberIndices, opt), nil
}

// registerRaceGroup appends the group placeholder upstream and wires the
// tag/group mappings. Returns the placeholder index.
func (s *Dns) registerRaceGroup(tag string, memberIndices []uint8, opt *NewOption) uint8 {
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
	if s.raceGroupIndices == nil {
		s.raceGroupIndices = map[uint8][]uint8{}
	}
	s.raceGroupIndices[placeholder] = memberIndices
	if s.raceTag2GroupIdx == nil {
		s.raceTag2GroupIdx = map[string]uint8{}
	}
	s.raceTag2GroupIdx[tag] = placeholder
	if s.raceGroupUpstreams == nil {
		s.raceGroupUpstreams = map[uint8]*Upstream{}
	}
	s.raceGroupUpstreams[placeholder] = &Upstream{
		Scheme:   UpstreamScheme_Race,
		Hostname: tag,
	}
	return placeholder
}

func (s *Dns) CheckUpstreamsFormat() error {
	for i, upstream := range s.upstream {
		// Skip race placeholder upstreams; they use a synthetic "race://" URL
		// and are never resolved directly.
		if _, isRace := s.raceGroupIndices[uint8(i)]; isRace {
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
	if _, isRace := s.raceGroupIndices[idx]; isRace {
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

// raceGroupUpstream returns the synthetic group upstream for a race placeholder
// index, resolving and caching its members on first use.
func (s *Dns) raceGroupUpstream(idx uint8) *Upstream {
	s.raceCacheMu.RLock()
	u := s.raceGroupUpstreams[idx]
	ready := u != nil && u.RaceGroup != nil && u.RaceGroup.Members != nil
	tag := ""
	if u != nil {
		tag = u.Hostname
	}
	s.raceCacheMu.RUnlock()
	if ready {
		return u
	}
	members := s.GetRaceUpstreams(consts.DnsRequestOutboundIndex(idx))
	if u == nil || len(members) == 0 {
		return nil
	}
	s.raceCacheMu.Lock()
	if u.RaceGroup == nil || u.RaceGroup.Members == nil {
		u.RaceGroup = &RaceGroup{Tag: tag, Members: members}
	}
	s.raceCacheMu.Unlock()
	return u
}

// GetRaceUpstreams returns resolved upstreams for a race group.
// Resolution happens lazily on first call and is cached thereafter.
// Returns nil if this index is not a race group.
func (s *Dns) GetRaceUpstreams(upstreamIndex consts.DnsRequestOutboundIndex) []*Upstream {
	idx := uint8(upstreamIndex)
	indices := s.raceGroupIndices[idx]
	if indices == nil {
		return nil
	}

	// Fast path: read lock, cache hit.
	s.raceCacheMu.RLock()
	if cached := s.raceUpstreams[idx]; cached != nil {
		s.raceCacheMu.RUnlock()
		return cached
	}
	s.raceCacheMu.RUnlock()

	// Slow path: write lock, resolve and cache.
	s.raceCacheMu.Lock()
	// Double-check: another goroutine may have populated it while we waited.
	if cached := s.raceUpstreams[idx]; cached != nil {
		s.raceCacheMu.Unlock()
		return cached
	}
	upstreams := make([]*Upstream, len(indices))
	for i, subIdx := range indices {
		up, err := s.upstream[subIdx].GetUpstream()
		if err != nil {
			s.raceCacheMu.Unlock()
			return nil
		}
		upstreams[i] = up
	}
	if s.raceUpstreams == nil {
		s.raceUpstreams = make(map[uint8][]*Upstream)
	}
	s.raceUpstreams[idx] = upstreams
	s.raceCacheMu.Unlock()
	return upstreams
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
