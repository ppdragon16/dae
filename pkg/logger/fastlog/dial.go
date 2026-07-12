/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package fastlog

import (
	"net/netip"

	"github.com/daeuniverse/outbound/pool"
)

// LogDial writes a connection-dial log line. All parameters are raw types;
// formatting (MAC, process name, address:port, etc.) is done inline with
// zero heap allocations in the logging framework.
//
// Output format:
//
//	time="..." level=info msg="[TCP] src <-> dst" network=tcp sniffed=example.com ip="1.2.3.4:80" pid=1234 ifindex=2 dscp=0 pname=curl mac="aa:bb:cc:dd:ee:ff" outbound=my-out ...
func LogDial(
	src, dst netip.AddrPort,
	network string, // e.g. "tcp4", "udp6" — from NetworkType.String()
	sniffed string, // sniffed domain, may be empty
	pname [16]uint8,
	mac [6]uint8,
	pid, ifindex uint32,
	dscp uint8,
	controlPlaneRoute bool,
	fallbackIpVersion bool,
	dialTarget string,
	fallback bool,
	outbound, policy, dialerName string,
	originalOutbound, originalPolicy, fallbackDialer string,
) {
	if std == nil {
		return
	}

	buf := pool.GetBuffer(512)[:0]
	ts := std.getTs()

	// Header: time + level
	buf = appendTs(buf, ts)
	buf = appendLvl(buf)

	// Message: [PROTO] src <-> dst  or  [PROTO] src <-(fallback)-> dst
	buf = append(buf, ` msg="`...)
	buf = append(buf, '[')
	buf = appendUpper(buf, network)
	if fallbackIpVersion {
		buf = append(buf, " (fallback)"...)
	}
	buf = append(buf, "] "...)
	buf = appendSource(buf, src, dst.Addr())
	if fallback {
		buf = append(buf, " <-(fallback)-> "...)
	} else {
		buf = append(buf, " <-> "...)
	}
	buf = append(buf, dialTarget...)
	buf = append(buf, '"')

	// Fields
	buf = appendStr(buf, "network", network)
	if sniffed != "" {
		buf = appendStr(buf, "sniffed", sniffed)
	}
	buf = append(buf, ` ip="`...)
	buf = appendAddrPort(buf, dst)
	buf = append(buf, '"')
	buf = appendUint(buf, "pid", pid)
	buf = appendUint(buf, "ifindex", ifindex)
	buf = appendUint(buf, "dscp", uint32(dscp))
	buf = appendPnameField(buf, pname)
	buf = appendMacField(buf, mac)

	if controlPlaneRoute {
		buf = appendBool(buf, "controlPlaneRoute", true)
	}

	if fallback {
		buf = appendStr(buf, "originalOutbound", originalOutbound)
		buf = appendStr(buf, "originalPolicy", originalPolicy)
		buf = appendStr(buf, "fallbackDialer", fallbackDialer)
	} else {
		buf = appendStr(buf, "outbound", outbound)
		buf = appendStr(buf, "policy", policy)
		buf = appendStr(buf, "dialer", dialerName)
	}

	buf = append(buf, '\n')

	std.writeBuf(buf)
	pool.PutBuffer(buf)
}
