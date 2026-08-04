/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"testing"

	dnsmessage "github.com/miekg/dns"
)

func buildLargeDNSResponse(t *testing.T, count int) *dnsmessage.Msg {
	t.Helper()
	msg := &dnsmessage.Msg{}
	msg.SetQuestion("cdn.example.com.", dnsmessage.TypeA)
	msg.Response = true
	msg.RecursionAvailable = true
	for i := 0; i < count; i++ {
		rr, err := dnsmessage.NewRR("cdn.example.com. 300 IN A 203.0.113.1")
		if err != nil {
			t.Fatalf("NewRR: %v", err)
		}
		msg.Answer = append(msg.Answer, rr)
	}
	return msg
}

func TestTruncateDNSResponse(t *testing.T) {
	// 35 A records exceed 512 bytes (the reported bug: CDN returns 35 A
	// records, packed size > 512, client got "noerror, 0 answer, tc=0").
	resp := buildLargeDNSResponse(t, 35)
	packed, err := resp.Pack()
	if err != nil {
		t.Fatalf("Pack: %v", err)
	}
	if len(packed) <= dnsDefaultUDPSize {
		t.Fatalf("test fixture too small: packed = %d bytes, want > %d", len(packed), dnsDefaultUDPSize)
	}

	resp.Truncate(dnsDefaultUDPSize)

	if !resp.Truncated {
		t.Fatal("truncated response must set TC bit")
	}
	if len(resp.Answer) == 0 {
		t.Fatal("truncated response should keep at least the answers that fit")
	}
	if len(resp.Question) == 0 {
		t.Fatal("truncated response must keep the question")
	}

	truncated, err := resp.Pack()
	if err != nil {
		t.Fatalf("Pack truncated: %v", err)
	}
	if len(truncated) > dnsDefaultUDPSize {
		t.Fatalf("truncated response still too large: %d > %d", len(truncated), dnsDefaultUDPSize)
	}
}

func TestTruncateDNSResponseSmall(t *testing.T) {
	// Responses within the limit must pass through untouched.
	resp := buildLargeDNSResponse(t, 2)
	packed, err := resp.Pack()
	if err != nil {
		t.Fatalf("Pack: %v", err)
	}

	resp.Truncate(dnsDefaultUDPSize)
	if resp.Truncated {
		t.Fatal("small response must not set TC bit")
	}

	truncated, err := resp.Pack()
	if err != nil {
		t.Fatalf("Pack truncated: %v", err)
	}
	if len(truncated) != len(packed) {
		t.Fatalf("small response was modified: %d -> %d bytes", len(packed), len(truncated))
	}
}

func TestDnsUDPResponseSizeLimit(t *testing.T) {
	// No EDNS0 -> classic 512.
	req := &dnsmessage.Msg{}
	req.SetQuestion("example.com.", dnsmessage.TypeA)
	limit := dnsDefaultUDPSize
	if opt := req.IsEdns0(); opt != nil {
		if s := int(opt.UDPSize()); s > limit {
			limit = s
		}
	}
	if limit != 512 {
		t.Fatalf("no-EDNS0 limit = %d, want 512", limit)
	}

	// EDNS0 with 4096 -> 4096.
	req2 := &dnsmessage.Msg{}
	req2.SetQuestion("example.com.", dnsmessage.TypeA)
	req2.SetEdns0(4096, true)
	limit2 := dnsDefaultUDPSize
	if opt := req2.IsEdns0(); opt != nil {
		if s := int(opt.UDPSize()); s > limit2 {
			limit2 = s
		}
	}
	if limit2 != 4096 {
		t.Fatalf("EDNS0 4096 limit = %d, want 4096", limit2)
	}

	// EDNS0 below 512 must be clamped up to 512 (RFC 6891 6.2.5).
	req3 := &dnsmessage.Msg{}
	req3.SetQuestion("example.com.", dnsmessage.TypeA)
	req3.SetEdns0(128, true)
	limit3 := dnsDefaultUDPSize
	if opt := req3.IsEdns0(); opt != nil {
		if s := int(opt.UDPSize()); s > limit3 {
			limit3 = s
		}
	}
	if limit3 != 512 {
		t.Fatalf("EDNS0 128 limit = %d, want 512", limit3)
	}
}
