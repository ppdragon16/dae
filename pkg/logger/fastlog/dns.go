/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package fastlog

import (
	"net/netip"

	"github.com/daeuniverse/outbound/pool"
)

// LogDnsResponse writes a DNS response log line. All parameters are raw
// types; formatting is done inline with zero heap allocations in the
// logging framework.
//
// Output format:
//
//	time="..." level=info msg="[DNS] src <-> dst" network=udp outbound=my-out policy=min dialer=my-dialer qname=example.com qtype=1 pid=1234 ...
//
// If accepted is false, " Reject with empty answer" is appended to the message.
func LogDnsResponse(
	src, dst netip.AddrPort, // source and original destination
	isTcp bool,
	actualTarget netip.AddrPort, // the actual upstream target dialed
	network string, // e.g. "udp4", "tcp6"
	outbound, policy, dialerName string,
	qname string,
	qtype uint16,
	pname [16]uint8,
	mac [6]uint8,
	pid, ifindex uint32,
	dscp uint8,
	accepted bool,
) {
	if !Enabled() {
		return
	}

	buf := pool.GetBuffer(512)[:0]
	ts := std.getTs()

	// Header: time + level
	buf = appendTs(buf, ts)
	buf = appendLvl(buf)

	// Message: [DNS(TCP)] src <-> target  [Reject with empty answer]
	buf = append(buf, ` msg="`...)
	if isTcp {
		buf = append(buf, "[DNS(TCP)] "...)
	} else {
		buf = append(buf, "[DNS] "...)
	}
	buf = appendSource(buf, src, dst.Addr())
	buf = append(buf, " <-> "...)
	if actualTarget == dst {
		buf = appendAddrPort(buf, actualTarget)
	} else {
		buf = appendAddrPort(buf, actualTarget)
		buf = append(buf, " ("...)
		buf = appendAddrPort(buf, dst)
		buf = append(buf, ')')
	}
	if !accepted {
		buf = append(buf, " Reject with empty answer"...)
	}
	buf = append(buf, '"')

	// Fields
	buf = appendStr(buf, "network", network)
	buf = appendStr(buf, "outbound", outbound)
	buf = appendStr(buf, "policy", policy)
	buf = appendStr(buf, "dialer", dialerName)
	buf = appendStr(buf, "qname", qname)
	buf = appendUint16(buf, "qtype", qtype)
	buf = appendUint(buf, "pid", pid)
	buf = appendUint(buf, "ifindex", ifindex)
	buf = appendUint(buf, "dscp", uint32(dscp))
	buf = appendPnameField(buf, pname)
	buf = appendMacField(buf, mac)

	buf = append(buf, '\n')

	std.writeBuf(buf)
	pool.PutBuffer(buf)
}

// rcodeNames indexes DNS response codes 0-15; rcode is a 4-bit header field,
// so the index is always in range.
var rcodeNames = [16]string{
	"NOERROR", "FORMERR", "SERVFAIL", "NXDOMAIN",
	"NOTIMP", "REFUSED", "YXDOMAIN", "YXRRSET",
	"NXRRSET", "NOTAUTH", "NOTZONE", "DSOTYPENI",
	"BADSIG", "BADKEY", "BADTIME", "BADMODE",
}

// LogDnsUpgrade writes the DNS response-phase upgrade line: a response rule
// discarded an answer and re-resolves the query against another upstream.
// All parameters are raw types; formatting is done inline with zero heap
// allocations in the logging framework.
//
// Output format:
//
//	time="..." level=info msg="[DNS] src <-> next (upgrade from last)" qname=example.com qtype=1 depth=1 rcode=NOERROR ips="1.2.3.4,5.6.7.8" ttl=60 ip_truncated=true
//
// More than 8 addresses are logged as the first 8 with ip_truncated=true.
func LogDnsUpgrade(
	src netip.AddrPort, // the querying client
	qname string,
	qtype uint16,
	depth uint32, // lookup round; upgrade #1 is the first re-resolution
	rcode uint8, // response code of the discarded answer
	ips []netip.Addr, // answer addresses of the discarded answer
	ttl uint32, // minimum TTL of those records
	lastUpstream, nextUpstream string,
) {
	if !Enabled() {
		return
	}
	// Cap the list: CDN answers can carry dozens of records, and the line
	// would bloat for every such answer.
	const maxLoggedIps = 8
	ipTruncated := len(ips) > maxLoggedIps
	if ipTruncated {
		ips = ips[:maxLoggedIps]
	}

	buf := pool.GetBuffer(512)[:0]
	ts := std.getTs()

	// Header: time + level
	buf = appendTs(buf, ts)
	buf = appendLvl(buf)

	// Message: [DNS] src <-> next (upgrade from last)
	buf = append(buf, ` msg="[DNS] `...)
	buf = appendAddrPort(buf, src)
	buf = append(buf, " <-> "...)
	buf = append(buf, nextUpstream...)
	buf = append(buf, ` (upgrade from `...)
	buf = append(buf, lastUpstream...)
	buf = append(buf, `)"`...)

	// Fields
	buf = appendStr(buf, "qname", qname)
	buf = appendUint16(buf, "qtype", qtype)
	buf = appendUint(buf, "depth", depth)
	if int(rcode) < len(rcodeNames) {
		buf = appendStr(buf, "rcode", rcodeNames[rcode])
	} else {
		buf = appendUint(buf, "rcode", uint32(rcode))
	}
	if len(ips) > 0 {
		// ips="1.2.3.4,5.6.7.8" — quoted unconditionally, so the comma list
		// never trips needsQuote per-address.
		buf = append(buf, ` ips="`...)
		for i, ip := range ips {
			if i > 0 {
				buf = append(buf, ',')
			}
			buf = ip.AppendTo(buf)
		}
		buf = append(buf, '"')
		buf = appendUint(buf, "ttl", ttl)
	}
	if ipTruncated {
		buf = appendBool(buf, "ip_truncated", true)
	}

	buf = append(buf, '\n')

	std.writeBuf(buf)
	pool.PutBuffer(buf)
}
