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

func New(dns *config.Dns, opt *NewOption) (s *Dns, err error) {
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
	// Initialize upstream name to id map.
	upstreamName2Id := map[string]uint8{}
	// Add static entries as virtual upstreams.
	// Each static entry becomes an upstream with scheme "static".
	for name := range dns.Static {
		staticUrl, err := url.Parse("static://" + name)
		if err != nil {
			return nil, fmt.Errorf("failed to parse static URL: %w", err)
		}
		r := &UpstreamResolver{
			Raw:     staticUrl,
			Network: opt.UpstreamResolverNetwork,
			FinishInitCallback: func(i int) func(raw *url.URL, upstream *Upstream) {
				return func(raw *url.URL, upstream *Upstream) {
					opt.UpstreamReadyCallback(upstream)
					s.upstream2IndexMu.Lock()
					s.upstream2Index[upstream] = i
					s.upstream2IndexMu.Unlock()
				}
			}(len(s.upstream)),
			mu:       sync.Mutex{},
			upstream: nil,
		}
		upstreamName2Id[name] = uint8(len(s.upstream))
		s.upstream = append(s.upstream, r)
	}
	// Parse upstream.
	for i, upstreamRaw := range dns.Upstream {
		if i >= int(consts.DnsRequestOutboundIndex_UserDefinedMax) ||
			i >= int(consts.DnsResponseOutboundIndex_UserDefinedMax) {
			return nil, fmt.Errorf("too many upstreams")
		}

		tag, link := common.GetTagFromLinkLikePlaintext(string(upstreamRaw))
		if tag == "" {
			return nil, fmt.Errorf("%w: '%v' has no tag", ErrBadUpstreamFormat, upstreamRaw)
		}
		var u *url.URL
		u, err = url.Parse(link)
		if err != nil {
			return nil, fmt.Errorf("%w: %v", ErrBadUpstreamFormat, err)
		}
		r := &UpstreamResolver{
			Raw:     u,
			Network: opt.UpstreamResolverNetwork,
			FinishInitCallback: func(i int) func(raw *url.URL, upstream *Upstream) {
				return func(raw *url.URL, upstream *Upstream) {
					opt.UpstreamReadyCallback(upstream)
					s.upstream2IndexMu.Lock()
					s.upstream2Index[upstream] = i
					s.upstream2IndexMu.Unlock()
				}
			}(i),
			mu:       sync.Mutex{},
			upstream: nil,
		}
		upstreamName2Id[tag] = uint8(len(s.upstream))
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
	if _, ok := s.staticEntries[name]; ok {
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
