/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package fastlog

import (
	"net/netip"
	"time"

	"github.com/daeuniverse/outbound/pool"
)

// SniffTimeoutCause classifies what a sniffing timeout saw. The mapping is
// exact rather than heuristic: the TLS parser only asks for more data after a
// handshake record header declares a length that has not arrived, and the HTTP
// parser only after a valid method prefix (which requires a printable first
// byte); every other shape returns a terminal verdict and never times out.
type SniffTimeoutCause uint8

const (
	// SniffTimeoutNoFirstByte: the peer never sent anything. Remote-first
	// protocols (ftp, smtp, ssh banners), browser preconnects/happy-eyeballs,
	// pool warmups and probes all look like this, and relaying continues by
	// design.
	SniffTimeoutNoFirstByte SniffTimeoutCause = iota
	// SniffTimeoutPartialTLS: a handshake record started but never completed
	// inside the budget (a ClientHello split across segments, or its tail
	// delayed by a retransmission).
	SniffTimeoutPartialTLS
	// SniffTimeoutPartialHTTP: a request line arrived but the header block did
	// not finish inside the budget.
	SniffTimeoutPartialHTTP
)

// String is the constant label used in the log line (no allocation: every
// return value is a compile-time string).
func (c SniffTimeoutCause) String() string {
	switch c {
	case SniffTimeoutPartialTLS:
		return "partial TLS record"
	case SniffTimeoutPartialHTTP:
		return "partial HTTP header"
	default:
		return "no first byte"
	}
}

// LogSniffTimeout writes a sniffing-timeout log line.
//
// Output format (record_* only for a partial TLS record, head only when bytes
// arrived):
//
//	time="..." level=info msg="Sniffing timeout" src=192.0.2.10:34567 dst=198.51.100.20:443 bytes=100 elapsed_ms=300 cause="partial TLS record" record_len=512 record_got=95 head="16 03 01 02 00"
//
// Kept allocation-free like the other high-frequency events: flat arguments, a
// pooled buffer and append-based encoding, with no logrus.Fields map and no
// per-field formatting.
func LogSniffTimeout(
	src, dst netip.AddrPort,
	cause SniffTimeoutCause,
	bytesRead, recordLen, recordGot int,
	head []byte,
	elapsed time.Duration,
) {
	if std == nil {
		return
	}

	buf := pool.GetBuffer(512)[:0]

	buf = appendTs(buf, std.getTs())
	buf = appendLvl(buf)
	buf = append(buf, ` msg="Sniffing timeout"`...)
	buf = appendAddrPortField(buf, "src", src)
	buf = appendAddrPortField(buf, "dst", dst)
	buf = appendUint(buf, "bytes", uint32(bytesRead))
	buf = appendUint(buf, "elapsed_ms", uint32(elapsed.Milliseconds()))
	buf = appendStr(buf, "cause", cause.String())
	if cause == SniffTimeoutPartialTLS {
		buf = appendUint(buf, "record_len", uint32(recordLen))
		buf = appendUint(buf, "record_got", uint32(recordGot))
	}
	if len(head) > 0 {
		buf = appendHexField(buf, "head", head)
	}
	buf = append(buf, '\n')

	std.writeBuf(buf)
	pool.PutBuffer(buf)
}
