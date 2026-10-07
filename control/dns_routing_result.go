/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"net/netip"
	"sync/atomic"
	"time"

	log "github.com/sirupsen/logrus"
)

// dnsRoutingLookup mirrors controlPlaneCore.RetrieveUDPRoutingResult /
// RetrieveTCPRoutingResult. The indirection exists so the fallback policy below
// is testable without eBPF maps.
type dnsRoutingLookup func(src, dst netip.AddrPort, out *bpfRoutingResult) error

// resolveUdpDnsRoutingResult fetches the routing result of a UDP DNS flow.
//
// The dataplane keys UDP DNS tuples with sport=0, so all queries from one IP
// share a single routing decision: that key is tried first. The flow's real
// source port is tried second, in case an entry was recorded under it anyway.
//
// When neither key exists — the dataplane failed to record the flow, e.g. a
// transient map update failure under a flow storm — the DNS query is NOT failed:
// a zeroed result is returned with cacheable=false. The DNS control plane needs
// no routing result to answer static/local entries (a pure in-process reply),
// and upstream queries still follow dae's own DNS request routing, so failing
// open here cannot leak traffic the way bypassing a proxy would. The result
// must not be cached, so the next query re-probes the map.
func resolveUdpDnsRoutingResult(lookup dnsRoutingLookup, src, dst netip.AddrPort) (result *bpfRoutingResult, cacheable bool) {
	result = new(bpfRoutingResult)
	if lookup(netip.AddrPortFrom(src.Addr(), 0), dst, result) == nil {
		return result, true
	}
	*result = bpfRoutingResult{}
	if lookup(src, dst, result) == nil {
		return result, true
	}
	// Fail open: Must stays 0, so the packet is hijacked into DNS control.
	*result = bpfRoutingResult{}
	return result, false
}

// dnsRoutingMissLogAt throttles the "no routing result for DNS" warning to one
// line per second. A flow storm (or a flood) makes every DNS packet miss, and an
// unthrottled per-packet log would amplify the event into the log and the disk.
var dnsRoutingMissLogAt atomic.Int64

func logDnsRoutingMissThrottled(src, dst netip.AddrPort) {
	now := time.Now().UnixNano()
	last := dnsRoutingMissLogAt.Load()
	if now-last < int64(time.Second) {
		return
	}
	if !dnsRoutingMissLogAt.CompareAndSwap(last, now) {
		return
	}
	log.WithFields(log.Fields{
		"src": src.String(),
		"dst": dst.String(),
	}).Warnln("No routing result for this DNS flow; answering without it (static/local entries are unaffected)")
}
