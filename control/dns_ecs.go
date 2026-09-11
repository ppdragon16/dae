/*
*  SPDX-License-Identifier: AGPL-3.0-only
*  Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net/netip"
	"strings"

	"github.com/daeuniverse/dae/component/outbound"
	"github.com/daeuniverse/dae/component/outbound/dialer"
	"github.com/daeuniverse/outbound/pool"
)

// Raw-byte EDNS0 Client Subnet (RFC 7871) rewriting, in the same
// wire-surgery style as dnsUDPPayloadSize/truncateDNSResponse: no
// dnsmessage.Msg unpack on the hot path, and the input query is never
// mutated (it is shared across racing dialers on the happy-eyeballs
// path). Rewrites return a fresh pooled buffer only when the message
// actually changes; otherwise the original slice is returned as-is.
const (
	dnsTypeOPT    = 41 // dnsmessage.TypeOPT
	dnsOptCodeEcs = 8  // EDNS0 option: Client Subnet

	dnsEcsFamilyV4 = 1
	dnsEcsFamilyV6 = 2

	// dnsInjectedUdpSize is the UDP payload size advertised by an OPT
	// record we inject (when the client sent no EDNS0). 1232 is the
	// DNS flag-day value: large enough for typical answers, small
	// enough to avoid IPv6/PPPoE fragmentation. Responses oversized
	// for the *client* are still truncated per its own request via
	// truncateDNSResponse.
	dnsInjectedUdpSize = 1232
)

// ParseEcsDefault validates the global dns.ecs option: "strip" (the
// default) or "pass". It deliberately rejects CIDR values — a global
// subnet would be wrong for every exit but one; use per-dialer
// [ecs: ...] annotations for explicit prefixes.
func ParseEcsDefault(val string) (*dialer.EcsSpec, error) {
	switch strings.TrimSpace(val) {
	case dialer.EcsModeStrip:
		return &dialer.EcsSpec{Strip: true, Key: dialer.EcsModeStrip}, nil
	case "", dialer.EcsModePass:
		// nil means pass-through.
		return nil, nil
	default:
		return nil, fmt.Errorf("invalid dns.ecs value %q: want 'strip' or 'pass'", val)
	}
}

// resolveEcsPolicy resolves the effective ECS policy: the annotation on
// the dialer in the context of its group wins; otherwise the global
// dns.ecs default applies (nil = pass-through).
func (c *DnsController) resolveEcsPolicy(outboundArg *outbound.DialerGroup, dialer *dialer.Dialer) *dialer.EcsSpec {
	if outboundArg != nil && dialer != nil {
		if anno := outboundArg.GetAnnotation(dialer); anno != nil && anno.Ecs != nil {
			return anno.Ecs
		}
	}
	return c.ecsDefaultSpec
}

// dnsRewriteEcs applies the policy to a raw DNS query.
//   - nil or pass-through policy: the query is forwarded as-is.
//   - strip policy: removes the EDNS0 Client Subnet option; the OPT
//     record is removed entirely when left with no options.
//   - prefix policy: injects an ECS option (adding an OPT record when
//     the client sent none) or replaces the client's ECS option.
//
// Returns (rewritten, changed). The input is never mutated.
func dnsRewriteEcs(data []byte, spec *dialer.EcsSpec) ([]byte, bool) {
	if spec == nil || spec.PassThrough || len(data) < 12 {
		return data, false
	}
	if spec.Strip {
		return dnsStripEcs(data)
	}
	if !spec.Prefix.IsValid() {
		return data, false
	}
	return dnsSetEcs(data, spec.Prefix)
}

// dnsQuestionSectionEnd returns the offset just past the question
// section.
func dnsQuestionSectionEnd(data []byte) (int, bool) {
	off := 12
	qdCount := int(binary.BigEndian.Uint16(data[4:6]))
	for range qdCount {
		next, err := dnsSkipDomain(data, off)
		if err != nil {
			return 0, false
		}
		off = next + 4 // QTYPE(2) + QCLASS(2)
		if off > len(data) {
			return 0, false
		}
	}
	return off, true
}

// dnsFindOpt locates the OPT pseudo-record in the additional section.
// Returns (rrStart, rdStart, rdLen, ok): rrStart is the offset of the
// record name; rdStart/rdLen delimit its RDATA.
func dnsFindOpt(data []byte) (rrStart, rdStart, rdLen int, ok bool) {
	arCount := int(binary.BigEndian.Uint16(data[10:12]))
	off, qdOk := dnsQuestionSectionEnd(data)
	if !qdOk {
		return 0, 0, 0, false
	}
	skipRr := func() bool {
		next, err := dnsSkipDomain(data, off)
		if err != nil {
			return false
		}
		if next+10 > len(data) {
			return false
		}
		off = next + 10 + int(binary.BigEndian.Uint16(data[next+8:next+10]))
		return off <= len(data)
	}
	for range anCount(data) {
		if !skipRr() {
			return 0, 0, 0, false
		}
	}
	for range nsCount(data) {
		if !skipRr() {
			return 0, 0, 0, false
		}
	}
	for range arCount {
		// OPT uses a root name (single zero byte).
		if off < len(data) && data[off] == 0 {
			// Fixed part after the name: TYPE(2)+CLASS(2)+TTL(4)+RDLENGTH(2).
			if off+11 > len(data) {
				return 0, 0, 0, false
			}
			if binary.BigEndian.Uint16(data[off+1:off+3]) == dnsTypeOPT {
				rrStart = off
				rdStart = off + 11
				rdLen = int(binary.BigEndian.Uint16(data[off+9 : off+11]))
				return rrStart, rdStart, rdLen, rdStart+rdLen <= len(data)
			}
		}
		if !skipRr() {
			return 0, 0, 0, false
		}
	}
	return 0, 0, 0, false
}

func anCount(data []byte) int { return int(binary.BigEndian.Uint16(data[6:8])) }
func nsCount(data []byte) int { return int(binary.BigEndian.Uint16(data[8:10])) }

// ecsOption is one parsed EDNS0 Client Subnet option: its span within a
// buffer and its fields.
type ecsOption struct {
	start, end int // span of the whole option (code+len+data)
	family     uint16
	srcBits    uint8
	scopeBits  uint8
	addr       []byte // the significant address octets
}

// findEcsOption scans OPT RDATA [start, start+rdLen) for the Client
// Subnet option.
func findEcsOption(data []byte, start, rdLen int) (ecsOption, bool) {
	off := start
	end := start + rdLen
	for off+4 <= end {
		optLen := int(binary.BigEndian.Uint16(data[off+2 : off+4]))
		if off+4+optLen > end {
			return ecsOption{}, false
		}
		if binary.BigEndian.Uint16(data[off:off+2]) == dnsOptCodeEcs {
			if optLen < 4 {
				return ecsOption{}, false
			}
			o := ecsOption{
				start:     off,
				end:       off + 4 + optLen,
				family:    binary.BigEndian.Uint16(data[off+4 : off+6]),
				srcBits:   data[off+6],
				scopeBits: data[off+7],
			}
			addrLen := optLen - 4
			o.addr = data[off+8 : off+8+addrLen]
			return o, true
		}
		off += 4 + optLen
	}
	return ecsOption{}, false
}

// dnsStripEcs removes the ECS option from the query. When the OPT record
// is left with no options, the record itself is removed and ARCOUNT is
// decremented.
func dnsStripEcs(data []byte) ([]byte, bool) {
	rrStart, rdStart, rdLen, ok := dnsFindOpt(data)
	if !ok {
		return data, false
	}
	opt, hasEcs := findEcsOption(data, rdStart, rdLen)
	if !hasEcs {
		return data, false
	}
	if opt.end-opt.start == rdLen {
		// OPT carried only the ECS option: drop the whole record.
		recordLen := (rdStart + rdLen) - rrStart
		out := pool.GetBuffer(len(data) - recordLen)[:len(data)-recordLen]
		copy(out, data[:rrStart])
		copy(out[rrStart:], data[rrStart+recordLen:])
		decrementArcount(out)
		return out, true
	}
	// Drop just the option; shrink RDLENGTH accordingly.
	removed := opt.end - opt.start
	out := pool.GetBuffer(len(data) - removed)[:len(data)-removed]
	copy(out, data[:opt.start])
	copy(out[opt.start:], data[opt.end:])
	binary.BigEndian.PutUint16(out[rrStart+9:rrStart+11], uint16(rdLen-removed))
	return out, true
}

// dnsSetEcs injects or replaces the ECS option so that the forwarded
// query carries exactly prefix (host bits already masked). Returns the
// message unchanged when it already carries an identical ECS option.
func dnsSetEcs(data []byte, prefix netip.Prefix) ([]byte, bool) {
	a := prefix.Addr()
	var family uint16
	var addr []byte
	if a.Is4() || a.Is4In6() {
		family = dnsEcsFamilyV4
		v4 := a.As4()
		addr = v4[:]
	} else {
		family = dnsEcsFamilyV6
		v6 := a.As16()
		addr = v6[:]
	}
	srcBits := prefix.Bits()
	if srcBits < 0 || srcBits > 128 {
		// Invalid prefix (e.g. the zero netip.Prefix): treat as no policy.
		return data, false
	}
	addrLen := (srcBits + 7) / 8
	// New ECS option wire bytes: CODE(2) + OPTION-LENGTH(2) + option data
	// = FAMILY(2) + SOURCE PREFIX-LENGTH(1) + SCOPE PREFIX-LENGTH(1) + ADDRESS.
	//
	// Stack-allocated: make() with a non-constant length always heap-
	// allocates even when it does not escape, but a fixed-capacity array
	// sliced down does not. Max size = 4 + 4 + 16 (IPv6 /128).
	var optBuf [8 + 16]byte
	newOpt := optBuf[:4+4+addrLen]
	dataLen := 4 + addrLen
	binary.BigEndian.PutUint16(newOpt[0:2], dnsOptCodeEcs)
	binary.BigEndian.PutUint16(newOpt[2:4], uint16(dataLen))
	binary.BigEndian.PutUint16(newOpt[4:6], family)
	newOpt[6] = uint8(srcBits)
	newOpt[7] = 0 // SCOPE PREFIX-LENGTH must be 0 in queries.
	copy(newOpt[8:], addr[:addrLen])

	rrStart, rdStart, rdLen, hasOpt := dnsFindOpt(data)
	if !hasOpt {
		// Append: OPT record + ECS option, then bump ARCOUNT.
		// Record: root name(1) type(2) class=udpsize(2) ttl(4) rdlen(2).
		recordLen := 11 + len(newOpt)
		out := pool.GetBuffer(len(data) + recordLen)[:len(data)+recordLen]
		copy(out, data)
		pos := len(data)
		out[pos] = 0
		binary.BigEndian.PutUint16(out[pos+1:pos+3], dnsTypeOPT)
		binary.BigEndian.PutUint16(out[pos+3:pos+5], dnsInjectedUdpSize)
		for i := 0; i < 4; i++ {
			out[pos+5+i] = 0 // extended rcode / version / flags
		}
		binary.BigEndian.PutUint16(out[pos+9:pos+11], uint16(len(newOpt)))
		copy(out[pos+11:], newOpt)
		incrementArcount(out)
		return out, true
	}

	if old, hasEcs := findEcsOption(data, rdStart, rdLen); hasEcs {
		if old.srcBits == newOpt[6] && old.scopeBits == 0 && old.family == family &&
			len(old.addr) == addrLen && bytes.Equal(old.addr, addr[:addrLen]) {
			return data, false
		}
		// Rebuild the OPT RDATA without the old ECS option, then append
		// the new one at the end (option order is insignificant).
		kept := rdLen - (old.end - old.start)
		newRdLen := kept + len(newOpt)
		outLen := len(data) - (old.end - old.start) + len(newOpt)
		out := pool.GetBuffer(outLen)[:outLen]
		copy(out, data[:rdStart])
		// Copy other options, skipping the old ECS option.
		copy(out[rdStart:], data[rdStart:old.start])
		copy(out[old.start:], data[old.end:rdStart+rdLen])
		copy(out[rdStart+kept:], newOpt)
		binary.BigEndian.PutUint16(out[rrStart+9:rrStart+11], uint16(newRdLen))
		return out, true
	}

	// OPT exists without an ECS option: append the option into its
	// RDATA.
	newRdLen := rdLen + len(newOpt)
	outLen := len(data) + len(newOpt)
	out := pool.GetBuffer(outLen)[:outLen]
	copy(out, data[:rdStart+rdLen])
	copy(out[rdStart+rdLen:], newOpt)
	binary.BigEndian.PutUint16(out[rrStart+9:rrStart+11], uint16(newRdLen))
	return out, true
}

func decrementArcount(data []byte) {
	ar := binary.BigEndian.Uint16(data[10:12])
	binary.BigEndian.PutUint16(data[10:12], ar-1)
}

func incrementArcount(data []byte) {
	ar := binary.BigEndian.Uint16(data[10:12])
	binary.BigEndian.PutUint16(data[10:12], ar+1)
}
