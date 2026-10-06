/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"hash/maphash"
	"testing"

	dnsmessage "github.com/miekg/dns"

	"github.com/daeuniverse/dae/component/dns"
)

// TestSingleFlightKeySeparatesUpstreams pins the flight-key contract the race
// path relies on: two members of one race group resolve to different upstream
// pointers and must therefore fly separately (so both upstreams are queried
// and a down upstream fails over to the other), while repeated keys for the
// same upstream still merge into one flight.
func TestSingleFlightKeySeparatesUpstreams(t *testing.T) {
	c := &DnsController{dnsCacheHashSeed: maphash.MakeSeed()}
	qi := queryInfo{qname: "race.example.com.", qtype: dnsmessage.TypeA}
	dialArg := &dialArgument{}
	u1 := &dns.Upstream{Scheme: dns.UpstreamScheme_UDP, Hostname: "1.1.1.1", Port: 53}
	u2 := &dns.Upstream{Scheme: dns.UpstreamScheme_UDP, Hostname: "8.8.8.8", Port: 53}

	k1a := c.singleFlightKey(qi, u1, dialArg)
	k1b := c.singleFlightKey(qi, u1, dialArg)
	k2 := c.singleFlightKey(qi, u2, dialArg)

	if k1a != k1b {
		t.Fatalf("same upstream must map to a single flight key: %v != %v", k1a, k1b)
	}
	if k1a == k2 {
		t.Fatalf("different upstreams must not share a flight key: race would collapse into one upstream query")
	}
}
