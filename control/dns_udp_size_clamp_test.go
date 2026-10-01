/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"bytes"
	"net"
	"net/netip"
	"testing"

	"github.com/daeuniverse/dae/component/outbound/dialer"
	dnsmessage "github.com/miekg/dns"
)

// queryWithUDPSize builds a wire-format query whose OPT advertises udpSize.
func queryWithUDPSize(t *testing.T, udpSize uint16, opts []dnsmessage.EDNS0) []byte {
	t.Helper()
	opt := &dnsmessage.OPT{
		Hdr:    dnsmessage.RR_Header{Name: ".", Rrtype: dnsmessage.TypeOPT},
		Option: opts,
	}
	opt.SetUDPSize(udpSize)
	return mustPackQuery(t, []dnsmessage.RR{opt})
}

// TestDnsClampUDPSizeLowersOversizedAdvertisement pins the request-side half
// of option B: a client that advertises a large UDP payload size gets it
// clamped before the query is forwarded, so a plain UDP upstream signals TC
// instead of sending an answer dae's MTU-sized read buffer would truncate.
func TestDnsClampUDPSizeLowersOversizedAdvertisement(t *testing.T) {
	data := queryWithUDPSize(t, 4096, nil)
	original := append([]byte(nil), data...)

	out, changed := dnsClampUDPSize(data, dnsUDPPayloadCap)
	if !changed {
		t.Fatal("a 4096-byte advertisement must be clamped")
	}
	if !bytes.Equal(data, original) {
		t.Fatal("the caller's bytes must not be mutated")
	}

	// Only the advertised size may change: the OPT CLASS field.
	rrStart, _, _, ok := dnsFindOpt(data)
	if !ok {
		t.Fatal("test query lost its OPT record")
	}
	if bytes.Equal(out[rrStart+3:rrStart+5], data[rrStart+3:rrStart+5]) {
		t.Fatal("advertised size bytes were not rewritten")
	}
	for i := range out {
		if i >= rrStart+3 && i < rrStart+5 {
			continue
		}
		if out[i] != data[i] {
			t.Fatalf("byte %d changed outside the advertised size field", i)
		}
	}
	if len(out) != len(data) {
		t.Fatalf("length changed: %d -> %d", len(data), len(out))
	}
	if got := findOptUDPSize(t, out); got != dnsUDPPayloadCap {
		t.Fatalf("advertised size = %d, want %d", got, dnsUDPPayloadCap)
	}
	mustUnpack(t, out)
}

// TestDnsClampUDPSizeKeepsAdvertisementsAtOrBelowTheCap guards against
// over-firing: sizes dae is willing to read must be forwarded untouched.
func TestDnsClampUDPSizeKeepsAdvertisementsAtOrBelowTheCap(t *testing.T) {
	for _, size := range []uint16{512, dnsUDPPayloadCap} {
		data := queryWithUDPSize(t, size, nil)
		out, changed := dnsClampUDPSize(data, dnsUDPPayloadCap)
		if changed {
			t.Fatalf("size %d must not be clamped", size)
		}
		if !bytes.Equal(out, data) {
			t.Fatalf("size %d was modified", size)
		}
	}
}

// TestDnsClampUDPSizeWithoutOPTIsANoOp keeps the classic (no EDNS0) query
// untouched: it already implies the 512-byte limit.
func TestDnsClampUDPSizeWithoutOPTIsANoOp(t *testing.T) {
	data := mustPackQuery(t, nil)
	out, changed := dnsClampUDPSize(data, dnsUDPPayloadCap)
	if changed || !bytes.Equal(out, data) {
		t.Fatal("a query without OPT must be forwarded unchanged")
	}
}

// TestRewriteUpstreamQueryComposesClampAndEcs pins the composition the
// forwarding path relies on: the clamp applies even when no ECS policy is
// configured, and when both rewrite, the ECS surgery preserves the clamped
// size (it copies the OPT header, including CLASS).
func TestRewriteUpstreamQueryComposesClampAndEcs(t *testing.T) {
	t.Run("clamp without ecs policy", func(t *testing.T) {
		data := queryWithUDPSize(t, 4096, nil)
		original := append([]byte(nil), data...)

		out, release := rewriteUpstreamQuery(data, nil)
		defer release()
		if got := findOptUDPSize(t, out); got != dnsUDPPayloadCap {
			t.Fatalf("advertised size = %d, want %d", got, dnsUDPPayloadCap)
		}
		if !bytes.Equal(data, original) {
			t.Fatal("the caller's bytes must not be mutated")
		}
	})

	t.Run("ecs injection uses the cap", func(t *testing.T) {
		data := mustPackQuery(t, nil)
		out, release := rewriteUpstreamQuery(data, &dialer.EcsSpec{
			Prefix: netip.MustParsePrefix("203.0.113.0/24"),
			Key:    "custom",
		})
		defer release()
		if got := findOptUDPSize(t, out); got != dnsUDPPayloadCap {
			t.Fatalf("injected OPT advertises %d, want %d", got, dnsUDPPayloadCap)
		}
		if e := findOptEcs(t, mustUnpack(t, out)); e == nil {
			t.Fatal("ECS option missing after injection")
		}
	})

	t.Run("strip preserves the clamped size", func(t *testing.T) {
		data := queryWithUDPSize(t, 4096, []dnsmessage.EDNS0{
			makeEcsOption(1, 24, net.IPv4(203, 0, 113, 0)),
			&dnsmessage.EDNS0_COOKIE{Code: dnsmessage.EDNS0COOKIE, Cookie: "0123456789abcdef"},
		})
		out, release := rewriteUpstreamQuery(data, &dialer.EcsSpec{Strip: true, Key: "strip"})
		defer release()
		if got := findOptUDPSize(t, out); got != dnsUDPPayloadCap {
			t.Fatalf("advertised size after strip = %d, want %d", got, dnsUDPPayloadCap)
		}
		m := mustUnpack(t, out)
		if e := findOptEcs(t, m); e != nil {
			t.Fatalf("ECS option survived the strip: %+v", e)
		}
	})

	t.Run("release is nil when nothing was rewritten", func(t *testing.T) {
		data := queryWithUDPSize(t, dnsUDPPayloadCap, nil)
		out, release := rewriteUpstreamQuery(data, nil)
		if release != nil {
			t.Fatal("release must be nil when no pooled buffer was taken")
		}
		if !bytes.Equal(out, data) {
			t.Fatal("a query at the cap must be forwarded unchanged")
		}
	})

	t.Run("release is set when rewritten", func(t *testing.T) {
		data := queryWithUDPSize(t, 4096, nil)
		_, release := rewriteUpstreamQuery(data, nil)
		if release == nil {
			t.Fatal("release must be set when a pooled buffer was taken")
		}
		release() // must be safe to call
	})
}

// findOptUDPSize returns the advertised UDP payload size of the first OPT.
func findOptUDPSize(t *testing.T, data []byte) uint16 {
	t.Helper()
	for _, rr := range mustUnpack(t, data).Extra {
		if opt, ok := rr.(*dnsmessage.OPT); ok {
			return opt.UDPSize()
		}
	}
	t.Fatal("no OPT record in message")
	return 0
}
