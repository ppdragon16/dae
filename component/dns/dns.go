/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package dns

import (
	"fmt"
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
	for _, upstreamRaw := range dns.Upstream {
		name, link := common.GetTagFromLinkLikePlaintext(string(upstreamRaw))
		if name == "" {
			return nil, fmt.Errorf("%w: '%v' has no tag", ErrBadUpstreamFormat, upstreamRaw)
		}
		u, err := url.Parse(link)
		if err != nil {
			return nil, fmt.Errorf("%w: %v", ErrBadUpstreamFormat, err)
		}
		predefinedUpstreamNames[name] = u
	}
	// Initialize upstream name to id map.
	upstreamName2Id := map[string]uint8{}
	for _, rule := range dns.Routing.Request.Rules {
		var urlKey string
		var rawURL *url.URL
		var ok bool
		var outboundIdx uint8
		outboundIdx = 0xFF
		upstreamName := rule.Outbound.Name
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
			urlKey = upstreamName
			upstreamName = upstreamName + "(" + outboundName + ")"
		} else if upstreamName == consts.Function_Race {
			// Race multiple upstreams: race(upstream1, upstream2, ...)
			// Create individual upstreams for each sub-name and a race group entry.
			var subIndices []uint8
			var subNames []string
			for _, p := range rule.Outbound.Params {
				if p.Key != "" {
					return nil, fmt.Errorf("race() only accepts bare upstream names, got key=%q", p.Key)
				}
				subName := p.Val
				if subName == "" {
					return nil, fmt.Errorf("race() requires non-empty upstream names")
				}
				subNames = append(subNames, subName)
				// Look up or create upstream for this sub-name.
				subIdx, exists := upstreamName2Id[subName]
				if !exists {
					if rawURL, ok = predefinedUpstreamNames[subName]; !ok {
						return nil, fmt.Errorf("Undefined upstream name %q in race()", subName)
					}
					subIdx = uint8(len(s.upstream))
					if currentUpstreamIndex := len(s.upstream); currentUpstreamIndex >= int(consts.OutboundUserDefinedMax) {
						return nil, fmt.Errorf("Too many upstreams")
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
					upstreamName2Id[subName] = subIdx
					s.upstream = append(s.upstream, r)
				}
				subIndices = append(subIndices, subIdx)
			}
			// Build the composite race upstream name.
			upstreamName = consts.Function_Race + "(" + strings.Join(subNames, ",") + ")"
			urlKey = upstreamName
			// Create a race placeholder upstream entry.
			raceIdx := uint8(len(s.upstream))
			if currentUpstreamIndex := len(s.upstream); currentUpstreamIndex >= int(consts.OutboundUserDefinedMax) {
				return nil, fmt.Errorf("Too many upstreams")
			}
			// Use a dummy URL for the race placeholder; it will never be resolved.
			dummyURL, err := url.Parse("race://" + strings.Join(subNames, ","))
			if err != nil {
				return nil, fmt.Errorf("failed to create race upstream URL: %w", err)
			}
			r := &UpstreamResolver{
				Raw:     dummyURL,
				Network: opt.UpstreamResolverNetwork,
				FinishInitCallback: func(i int, outbound uint8) func(raw *url.URL, upstream *Upstream) {
					return func(raw *url.URL, upstream *Upstream) {
						upstream.Outbound = consts.OutboundIndex(outbound)
						s.upstream2IndexMu.Lock()
						s.upstream2Index[upstream] = i
						s.upstream2IndexMu.Unlock()
					}
				}(len(s.upstream), outboundIdx),
				mu:       sync.Mutex{},
				upstream: nil,
			}
			upstreamName2Id[upstreamName] = raceIdx
			s.upstream = append(s.upstream, r)
			if s.raceGroupIndices == nil {
				s.raceGroupIndices = make(map[uint8][]uint8)
			}
			s.raceGroupIndices[raceIdx] = subIndices
			continue
		} else {
			urlKey = upstreamName
		}
		if urlKey == "asis" || urlKey == "reject" {
			continue
		}
		if rawURL, ok = predefinedUpstreamNames[urlKey]; !ok {
			return nil, fmt.Errorf("Undefined upstream name in dns routing rules: %s", upstreamName)
		}
		currentUpstreamIndex := len(s.upstream)
		if currentUpstreamIndex >= int(consts.OutboundUserDefinedMax) {
			return nil, fmt.Errorf("Too many upstreams")
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
	respMatcherBuilder, err := NewResponseMatcherBuilder(dns.Routing.Response.Rules, upstreamName2Id, dns.Routing.Response.Fallback)
	if err != nil {
		return nil, fmt.Errorf("failed to build DNS response routing: %w", err)
	}
	s.respMatcher, err = respMatcherBuilder.Build()
	if err != nil {
		return nil, fmt.Errorf("failed to build DNS response routing: %w", err)
	}
	return s, nil
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
	return s.upstream[upstreamIndex].GetUpstream()
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
	return fmt.Errorf("The entry '%s' doesn't exist", name)
}

func (s *Dns) GetStaticEntries() map[string]*config.DnsStaticEntry {
	s.staticEntriesMu.RLock()
	defer s.staticEntriesMu.RUnlock()
	// Return a copy to avoid race conditions
	result := make(map[string]*config.DnsStaticEntry, len(s.staticEntries))
	for k, v := range s.staticEntries {
		result[k] = v
	}
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

func (s *Dns) ResponseSelect(qname string, qtype uint16, ips []netip.Addr, fromUpstream *Upstream, srcMac [6]byte, srcIp netip.Addr) (upstreamIndex consts.DnsResponseOutboundIndex, upstream *Upstream, err error) {
	// Prepare routing.
	s.upstream2IndexMu.Lock()
	from := s.upstream2Index[fromUpstream]
	s.upstream2IndexMu.Unlock()
	// Route.
	upstreamIndex, err = s.respMatcher.Match(qname, qtype, ips, consts.DnsRequestOutboundIndex(from), srcMac, srcIp)
	if err != nil {
		return 0, nil, err
	}
	// Get corresponding upstream if upstream is neither 'accept' nor 'reject'.
	if !upstreamIndex.IsReserved() {
		if int(upstreamIndex) >= len(s.upstream) {
			return 0, nil, fmt.Errorf("bad upstream index: %v not in [0, %v]", upstreamIndex, len(s.upstream)-1)
		}
		upstream, err = s.upstream[upstreamIndex].GetUpstream()
		if err != nil {
			return 0, nil, err
		}
	} else {
		// Assign explicitly to let coder know.
		upstream = nil
	}
	return upstreamIndex, upstream, nil
}
