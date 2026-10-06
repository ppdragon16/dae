/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.us>
 */

package control

import (
	"hash/maphash"
	"net/netip"
	"testing"
	"time"

	dnsmessage "github.com/miekg/dns"

	"github.com/daeuniverse/dae/common"
	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/component/dns"
	"github.com/daeuniverse/dae/component/outbound"
	"github.com/daeuniverse/dae/component/outbound/dialer"
	D "github.com/daeuniverse/outbound/dialer"
	"github.com/daeuniverse/outbound/pool"
)

// BenchmarkDNSRequestSingleCacheHit pins the per-query cost of the steady state
// most deployments are in: one upstream (no race group) serving a fresh cache
// entry. Nothing here dials, so the numbers are the request phase plus the
// cache-read copy.
func BenchmarkDNSRequestSingleCacheHit(b *testing.B) {
	common.InitMetrics()
	option := &dialer.GlobalOption{
		CheckDnsOptionRaw: dialer.CheckDnsOptionRaw{Raw: []string{"1.1.1.1:53"}},
		CheckInterval:     time.Hour,
	}
	proxy := &raceStubProxy{}
	d := dialer.NewDialer(proxy, option, &dialer.Property{Property: D.Property{Name: "a"}}, false)
	group := outbound.NewDialerGroup(option, "grp-a", []*dialer.Dialer{d}, []*dialer.Annotation{{}},
		dialer.DialerSelectionPolicy{Policy: consts.DialerSelectionPolicy_Fixed, FixedIndex: 0},
		func(alive bool, networkType *common.NetworkType) {})
	up := raceTestUpstream("1.1.1.1")
	c := &DnsController{
		enableCache:      true,
		dnsCache:         NewCommonDnsCache(),
		dnsCacheHashSeed: maphash.MakeSeed(),
		routing:          &dns.Dns{},
		matchBitmap:      func(string, []uint32) {},
		bestDialerChooser: func(req *dnsRequest, upstream *dns.Upstream, outArg *dialArgument) error {
			outArg.Outbound, outArg.Dialer = group, d
			outArg.networkType = common.NETWORK_UDP4
			return nil
		},
	}
	const qname = "bench.example.com"
	key := c.GetHashKey(qname, uint16(dnsmessage.TypeA), group, d)
	c.dnsCache.Save(key, raceTestAnswer(b, qname, netip.MustParseAddr("198.51.100.1")), 600, false)
	// Consume IsNew so the eBPF epilogue stays out of the measurement.
	c.dnsCache.Get(key)

	req := ObtainDnsRequest(
		netip.MustParseAddrPort("192.168.16.129:44081"),
		netip.MustParseAddrPort("8.8.8.8:53"),
		&bpfRoutingResult{}, false)
	defer RecycleDnsRequest(req)
	data := raceTestAnswer(b, qname, netip.IPv4Unspecified())
	qi := queryInfo{qname: qname, qtype: uint16(dnsmessage.TypeA)}

	dnsResp := &dnsResponseData{}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if err := c.handleDNSRequestByUpstream(data, req, qi, up, dnsResp); err != nil {
			b.Fatal(err)
		}
		// Handle recycles the response buffer once it has written it back to
		// the client; without that the pool drains and every iteration pays a
		// buffer allocation that production does not.
		if dnsResp.respData != nil && dnsResp.fromPool {
			pool.PutBuffer(dnsResp.respData)
		}
		*dnsResp = dnsResponseData{}
	}
}
