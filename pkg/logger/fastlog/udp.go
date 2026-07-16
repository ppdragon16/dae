/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package fastlog

import (
	"net/netip"

	"github.com/daeuniverse/outbound/pool"
)

// LogUdpReply writes a UDP packet reply log line.
//
// Output format:
//
//	time="..." level=info msg="Received UDP packet reply: src <- from"
func LogUdpReply(src, from netip.AddrPort) {
	if std == nil {
		return
	}

	buf := pool.GetBuffer(128)[:0]
	ts := std.getTs()

	// Header: time + level
	buf = appendTs(buf, ts)
	buf = appendLvl(buf)

	// Message: "Received UDP packet reply: src <- from"
	buf = append(buf, ` msg="Received UDP packet reply: `...)
	buf = appendAddrPort(buf, src)
	buf = append(buf, " <- "...)
	buf = appendAddrPort(buf, from)
	buf = append(buf, '"')

	buf = append(buf, '\n')

	std.writeBuf(buf)
	pool.PutBuffer(buf)
}
