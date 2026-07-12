/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package fastlog

import (
	"net/netip"
	"strconv"
)

// All append functions return the extended slice and perform zero
// heap allocations (the compiler keeps scratch data on the stack).

// ---- header helpers ----

// appendTs appends:  time="Jan 02 15:04:05"
func appendTs(buf, ts []byte) []byte {
	buf = append(buf, `time="`...)
	buf = append(buf, ts...)
	buf = append(buf, '"')
	return buf
}

// appendLvl appends:  level=info
func appendLvl(buf []byte) []byte {
	return append(buf, " level=info"...)
}

// appendMsg appends:  msg="..."
func appendMsg(buf []byte, msg string) []byte {
	buf = append(buf, ` msg="`...)
	buf = append(buf, msg...)
	buf = append(buf, '"')
	return buf
}

// ---- field helpers ----

// appendStr appends:  key=val  (val quoted when it contains special chars,
// matching prefixed.TextFormatter.needsQuoting).
func appendStr(buf []byte, key, val string) []byte {
	buf = append(buf, ' ')
	buf = append(buf, key...)
	buf = append(buf, '=')
	if needsQuote(val) {
		buf = append(buf, '"')
		buf = append(buf, val...)
		buf = append(buf, '"')
	} else {
		buf = append(buf, val...)
	}
	return buf
}

// appendUint appends:  key=123  (zero alloc via strconv.AppendUint)
func appendUint(buf []byte, key string, v uint32) []byte {
	buf = append(buf, ' ')
	buf = append(buf, key...)
	buf = append(buf, '=')
	buf = strconv.AppendUint(buf, uint64(v), 10)
	return buf
}

// appendUint16 appends:  key=123  for uint16 values
func appendUint16(buf []byte, key string, v uint16) []byte {
	buf = append(buf, ' ')
	buf = append(buf, key...)
	buf = append(buf, '=')
	buf = strconv.AppendUint(buf, uint64(v), 10)
	return buf
}

// appendBool appends:  key=true  or  key=false
func appendBool(buf []byte, key string, v bool) []byte {
	buf = append(buf, ' ')
	buf = append(buf, key...)
	buf = append(buf, '=')
	if v {
		buf = append(buf, "true"...)
	} else {
		buf = append(buf, "false"...)
	}
	return buf
}

// ---- raw-type formatting helpers (zero alloc) ----

const hexDigits = "0123456789abcdef"

// appendMac appends a MAC address formatted as "aa:bb:cc:dd:ee:ff".
func appendMac(buf []byte, mac [6]uint8) []byte {
	for i, b := range mac {
		buf = append(buf, hexDigits[b>>4], hexDigits[b&0xf])
		if i < 5 {
			buf = append(buf, ':')
		}
	}
	return buf
}

// appendPname appends the process name, trimming trailing null bytes.
func appendPname(buf []byte, pname [16]uint8) []byte {
	end := 16
	for i, b := range pname {
		if b == 0 {
			end = i
			break
		}
	}
	buf = append(buf, pname[:end]...)
	return buf
}

// appendAddrPort appends an address:port using netip.AddrPort.AppendTo
// (IPv4: "1.2.3.4:443", IPv6: "[::1]:443").
func appendAddrPort(buf []byte, ap netip.AddrPort) []byte {
	return ap.AppendTo(buf)
}

// appendSource appends the source address for display. If src.Addr() == dst,
// outputs "localhost:port"; otherwise outputs the full address:port.
// Mirrors control.RefineSourceToShow.
func appendSource(buf []byte, src netip.AddrPort, dst netip.Addr) []byte {
	if src.Addr() == dst {
		buf = append(buf, "localhost:"...)
		buf = strconv.AppendUint(buf, uint64(src.Port()), 10)
	} else {
		buf = src.AppendTo(buf)
	}
	return buf
}

// appendUpper appends an ASCII-uppercased copy of s.
func appendUpper(buf []byte, s string) []byte {
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= 'a' && c <= 'z' {
			c -= 32
		}
		buf = append(buf, c)
	}
	return buf
}

// ---- field-level helpers with quoting ----

// appendPnameField appends " pname=..." with quoting if needed.
// Scans once to find the null terminator and check for special chars.
func appendPnameField(buf []byte, pname [16]uint8) []byte {
	end := 16
	needsQ := false
	for i, b := range pname {
		if b == 0 {
			end = i
			break
		}
		if !isSafeByte(b) {
			needsQ = true
		}
	}
	buf = append(buf, " pname="...)
	if needsQ {
		buf = append(buf, '"')
	}
	buf = append(buf, pname[:end]...)
	if needsQ {
		buf = append(buf, '"')
	}
	return buf
}

// appendMacField appends " mac="aa:bb:cc:dd:ee:ff"" (MAC always quoted
// because it contains colons).
func appendMacField(buf []byte, mac [6]uint8) []byte {
	buf = append(buf, " mac=\""...)
	buf = appendMac(buf, mac)
	buf = append(buf, '"')
	return buf
}

// isSafeByte returns true if b is safe to use unquoted in a log field value.
func isSafeByte(b uint8) bool {
	return (b >= 'a' && b <= 'z') ||
		(b >= 'A' && b <= 'Z') ||
		(b >= '0' && b <= '9') ||
		b == '-' || b == '.' || b == '_' || b == '/'
}

// ---- quoting ----

// needsQuote returns true if val contains characters that would break
// the key=value log format (spaces, special characters, etc.).
// Uses rune iteration so multi-byte UTF-8 characters (e.g. CJK) are
// handled correctly — they will be quoted.
// Mirrors prefixed.TextFormatter.needsQuoting (formatter.go:290-303).
func needsQuote(s string) bool {
	if len(s) == 0 {
		return true
	}
	for _, ch := range s {
		if !((ch >= 'a' && ch <= 'z') ||
			(ch >= 'A' && ch <= 'Z') ||
			(ch >= '0' && ch <= '9') ||
			ch == '-' || ch == '.') {
			return true
		}
	}
	return false
}
