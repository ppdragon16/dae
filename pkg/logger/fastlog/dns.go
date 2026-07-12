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
	if std == nil {
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
