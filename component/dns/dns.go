/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package dns

import (
	"fmt"
	"net/netip"
	"net/url"
	"sync"

	"github.com/daeuniverse/dae/common"
	"github.com/daeuniverse/dae/common/assets"
	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/component/routing"
	"github.com/daeuniverse/dae/config"
	dnsmessage "github.com/miekg/dns"
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

	// Process fallback upstreams that may not be referenced in any rule.
	// This ensures fallback upstreams are also registered in upstreamName2Id.
	if err = processFallbackUpstream(dns.Routing.Request.Fallback, predefinedUpstreamNames, outboundName2Id, upstreamName2Id, s, opt); err != nil {
		return nil, err
	}
	if err = processFallbackUpstream(dns.Routing.Response.Fallback, predefinedUpstreamNames, outboundName2Id, upstreamName2Id, s, opt); err != nil {
		return nil, err
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

// processFallbackUpstream ensures that upstreams referenced in fallback are registered
// in upstreamName2Id even if they are not used in any routing rule.
func processFallbackUpstream(fallback config.FunctionOrString, predefinedUpstreamNames map[string]*url.URL, outboundName2Id map[string]uint8, upstreamName2Id map[string]uint8, s *Dns, opt *NewOption) error {
	if fallback == nil {
		return nil
	}

	f := config.FunctionOrStringToFunction(fallback)
	if f == nil {
		return nil
	}

	upstreamName := f.Name
	var urlKey string
	var outboundIdx uint8 = 0xFF

	// Handle static entries
	if upstreamName == "static" {
		if len(f.Params) != 1 {
			return fmt.Errorf("'static' upstream takes only one parameter")
		}
		upstreamName = f.Params[0].Val
		urlKey = upstreamName
	} else if len(f.Params) == 1 && f.Params[0].Key == consts.OutboundParam_Via {
		// Handle proxy_dns(via: sg) format
		outboundName := f.Params[0].Val
		var ok bool
		outboundIdx, ok = outboundName2Id[outboundName]
		if !ok {
			return fmt.Errorf("outbound %q not found", outboundName)
		}
		urlKey = upstreamName
		upstreamName = upstreamName + "(" + outboundName + ")"
	} else {
		urlKey = upstreamName
	}

	// Skip special upstreams
	if urlKey == "asis" || urlKey == "reject" || urlKey == "accept" {
		return nil
	}

	// Check if already registered
	if _, ok := upstreamName2Id[upstreamName]; ok {
		return nil
	}

	// Look up the upstream URL
	rawURL, ok := predefinedUpstreamNames[urlKey]
	if !ok {
		return fmt.Errorf("Undefined upstream name in dns routing fallback: %s", upstreamName)
	}

	// Register the upstream
	if len(s.upstream) >= int(consts.OutboundUserDefinedMax) {
		return fmt.Errorf("Too many upstreams")
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

	return nil
}

func (s *Dns) CheckUpstreamsFormat() error {
	for _, upstream := range s.upstream {
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

func (s *Dns) RequestSelect(qname string, qtype uint16) (upstreamIndex consts.DnsRequestOutboundIndex, err error) {
	// Route.
	upstreamIndex, err = s.reqMatcher.Match(qname, qtype)
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

func (s *Dns) ResponseSelect(msg *dnsmessage.Msg, fromUpstream *Upstream) (upstreamIndex consts.DnsResponseOutboundIndex, upstream *Upstream, err error) {
	if !msg.Response {
		return 0, nil, fmt.Errorf("DNS response expected but DNS request received")
	}

	if !s.hasResponseRules {
		return consts.DnsResponseOutboundIndex_Accept, nil, nil
	}

	// Prepare routing.
	var qname string
	var qtype uint16
	var ips []netip.Addr
	if len(msg.Question) == 0 {
		qname = ""
		qtype = 0
	} else {
		q := msg.Question[0]
		qname = q.Name
		qtype = q.Qtype
		for _, ans := range msg.Answer {
			var (
				ip netip.Addr
				ok bool
			)
			switch body := ans.(type) {
			case *dnsmessage.A:
				ip, ok = netip.AddrFromSlice(body.A)
			case *dnsmessage.AAAA:
				ip, ok = netip.AddrFromSlice(body.AAAA)
			}
			if !ok {
				continue
			}
			ips = append(ips, ip)
		}
	}

	s.upstream2IndexMu.Lock()
	from := s.upstream2Index[fromUpstream]
	s.upstream2IndexMu.Unlock()
	// Route.
	upstreamIndex, err = s.respMatcher.Match(qname, qtype, ips, consts.DnsRequestOutboundIndex(from))
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
