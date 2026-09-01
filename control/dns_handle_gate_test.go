/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"testing"

	dnsmessage "github.com/miekg/dns"
)

// TestHandleDropsResponseFormedMessages pins that a client-supplied message
// with the QR bit set never enters request routing: Handle declines it and
// the caller falls through to regular UDP routing toward the original
// destination. Without the gate, Handle would clear the QR bit and launder
// the response into a query.
func TestHandleDropsResponseFormedMessages(t *testing.T) {
	msg := &dnsmessage.Msg{}
	msg.SetQuestion("drop.example.com.", dnsmessage.TypeA)
	data, err := msg.Pack()
	if err != nil {
		t.Fatalf("Pack: %v", err)
	}
	dnsResponseSet(data, true)
	if !dnsResponse(data) {
		t.Fatal("test setup: QR bit not set")
	}

	// The gate path touches no controller state, so a zero value exercises it.
	if (&DnsController{}).Handle(data, &dnsRequest{}) {
		t.Fatal("response-formed message must not be handled")
	}

	// The message must be returned untouched: the gate declines before the
	// unconditional QR clear further down would rewrite it.
	if !dnsResponse(data) {
		t.Fatal("gate must not mutate the message")
	}
}
