/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"testing"

	dnsmessage "github.com/miekg/dns"
)

// buildDNSQuery builds a minimal DNS query, optionally with an EDNS0 OPT
// record advertising the given UDP payload size (0 means no EDNS0).
func buildDNSQuery(t *testing.T, ednsSize int) []byte {
	t.Helper()
	req := &dnsmessage.Msg{}
	req.SetQuestion("cdn.example.com.", dnsmessage.TypeA)
	if ednsSize > 0 {
		req.SetEdns0(uint16(ednsSize), true)
	}
	data, err := req.Pack()
	if err != nil {
		t.Fatalf("Pack query: %v", err)
	}
	return data
}

// buildLargeDNSResponse builds a DNS response with many A records whose
// packed size exceeds the classic 512-byte UDP limit (e.g., a CDN returning
// 35 A records).
func buildLargeDNSResponse(t *testing.T, count int) (*dnsmessage.Msg, []byte) {
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
	data, err := msg.Pack()
	if err != nil {
		t.Fatalf("Pack: %v", err)
	}
	return msg, data
}

func TestTruncateDNSResponse(t *testing.T) {
	// 35 A records exceed 512 bytes (the reported bug: CDN returns 35 A
	// records, packed size > 512, client got "noerror, 0 answer, tc=0").
	_, respData := buildLargeDNSResponse(t, 35)
	if len(respData) <= dnsDefaultUDPSize {
		t.Fatalf("test fixture too small: packed = %d bytes, want > %d", len(respData), dnsDefaultUDPSize)
	}

	reqData := buildDNSQuery(t, 0) // no EDNS0 → limit=512
	truncated := truncateDNSResponse(reqData, respData)

	var resp dnsmessage.Msg
	if err := resp.Unpack(truncated); err != nil {
		t.Fatalf("Unpack truncated response: %v", err)
	}
	if !resp.Truncated {
		t.Fatal("truncated response must set TC bit")
	}
	if len(truncated) > dnsDefaultUDPSize {
		t.Fatalf("truncated response still too large: %d > %d", len(truncated), dnsDefaultUDPSize)
	}
	if len(resp.Answer) == 0 {
		t.Fatal("truncated response should keep at least the answers that fit")
	}
	if len(resp.Question) == 0 {
		t.Fatal("truncated response must keep the question")
	}
}

func TestTruncateDNSResponseSmall(t *testing.T) {
	// Responses within the limit must pass through untouched.
	_, respData := buildLargeDNSResponse(t, 2)
	reqData := buildDNSQuery(t, 0)

	truncated := truncateDNSResponse(reqData, respData)
	if len(truncated) != len(respData) {
		t.Fatalf("small response was modified: %d -> %d bytes", len(respData), len(truncated))
	}
}

func TestTruncateDNSResponseEDNS(t *testing.T) {
	// Client advertises EDNS0 4096 → 35 A records fit without truncation.
	_, respData := buildLargeDNSResponse(t, 35)
	reqData := buildDNSQuery(t, 4096)

	truncated := truncateDNSResponse(reqData, respData)
	if len(truncated) != len(respData) {
		t.Fatalf("EDNS0 4096: response was truncated: %d -> %d bytes", len(respData), len(truncated))
	}

	// Client advertises EDNS0 128 below 512 → limit clamped to 512 implicitly.
	// 35 A records > 512 so still truncated.
	reqData2 := buildDNSQuery(t, 128)
	truncated2 := truncateDNSResponse(reqData2, respData)
	if len(truncated2) >= len(respData) {
		t.Fatalf("EDNS0 128: response should be truncated (limit=512)")
	}
}

func TestDnsUDPPayloadSize(t *testing.T) {
	// No EDNS0 -> returns 0.
	req := &dnsmessage.Msg{}
	req.SetQuestion("example.com.", dnsmessage.TypeA)
	data, _ := req.Pack()
	if got := dnsUDPPayloadSize(data); got != 0 {
		t.Fatalf("no-EDNS0 payload size = %d, want 0", got)
	}

	// EDNS0 with 4096 -> 4096.
	req2 := &dnsmessage.Msg{}
	req2.SetQuestion("example.com.", dnsmessage.TypeA)
	req2.SetEdns0(4096, true)
	data2, _ := req2.Pack()
	if got := dnsUDPPayloadSize(data2); got != 4096 {
		t.Fatalf("EDNS0 4096 payload size = %d, want 4096", got)
	}

	// EDNS0 with 128 -> returns 128 (raw value, clamping is caller's job).
	req3 := &dnsmessage.Msg{}
	req3.SetQuestion("example.com.", dnsmessage.TypeA)
	req3.SetEdns0(128, true)
	data3, _ := req3.Pack()
	if got := dnsUDPPayloadSize(data3); got != 128 {
		t.Fatalf("EDNS0 128 payload size = %d, want 128", got)
	}
}
