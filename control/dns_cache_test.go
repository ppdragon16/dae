/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"testing"
	"time"

	"github.com/daeuniverse/dae/common"
	dnsmessage "github.com/miekg/dns"
)

// buildCacheableResponse packs a minimal DNS response with one A record so
// Save accepts it (anCount > 0, TTL >= minSaveTtl).
func buildCacheableResponse(t *testing.T) []byte {
	t.Helper()
	msg := &dnsmessage.Msg{}
	msg.SetQuestion("backoff.example.com.", dnsmessage.TypeA)
	rr, err := dnsmessage.NewRR("backoff.example.com. 300 IN A 203.0.113.1")
	if err != nil {
		t.Fatalf("NewRR: %v", err)
	}
	msg.Answer = []dnsmessage.RR{rr}
	data, err := msg.Pack()
	if err != nil {
		t.Fatalf("Pack: %v", err)
	}
	return data
}

func TestDnsCacheRefreshBackoff(t *testing.T) {
	common.InitMetrics()
	c := NewCommonDnsCache()
	defer func() { _ = c.Close() }()

	key := HashKey(1)
	c.Save(key, buildCacheableResponse(t), 0, false)

	t0 := time.Now()

	// First failure: backoff window is exactly dnsRefreshBackoffInitial.
	c.PostponeRefresh(key, t0)
	if !c.RefreshDelayed(key, t0.Add(dnsRefreshBackoffInitial-time.Second)) {
		t.Fatalf("entry should be delayed just after the first failure")
	}
	if c.RefreshDelayed(key, t0.Add(dnsRefreshBackoffInitial+time.Second)) {
		t.Fatalf("entry should be refreshable again after the initial window")
	}

	// Second failure doubles the window.
	t1 := t0.Add(dnsRefreshBackoffInitial + time.Second)
	c.PostponeRefresh(key, t1)
	if !c.RefreshDelayed(key, t1.Add(dnsRefreshBackoffInitial*2-time.Second)) {
		t.Fatalf("entry should be delayed for the doubled window")
	}
	if c.RefreshDelayed(key, t1.Add(dnsRefreshBackoffInitial*2+time.Second)) {
		t.Fatalf("entry should be refreshable again after the doubled window")
	}

	// Repeated failures cap at dnsRefreshBackoffMax.
	last := t1
	for i := 0; i < 20; i++ {
		last = last.Add(time.Minute)
		c.PostponeRefresh(key, last)
	}
	if !c.RefreshDelayed(key, last.Add(dnsRefreshBackoffMax-time.Second)) {
		t.Fatalf("entry should be delayed up to the cap")
	}
	if c.RefreshDelayed(key, last.Add(dnsRefreshBackoffMax+time.Second)) {
		t.Fatalf("entry should be refreshable again after the cap")
	}

	// A successful Save replaces the entry and clears the backoff with it.
	c.Save(key, buildCacheableResponse(t), 0, false)
	if c.RefreshDelayed(key, last.Add(time.Second)) {
		t.Fatalf("a freshly saved entry must not be delayed")
	}

	// Unknown keys are never delayed.
	if c.RefreshDelayed(HashKey(999), time.Now()) {
		t.Fatalf("unknown key must not be delayed")
	}
}
