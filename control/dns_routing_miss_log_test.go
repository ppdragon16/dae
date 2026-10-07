/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"bytes"
	"net/netip"
	"strings"
	"testing"
	"time"

	log "github.com/sirupsen/logrus"
)

// TestLogDnsRoutingMissThrottled pins the anti-amplification property of the
// fail-open path: a storm of misses must produce one log line per second, not
// one per packet.
func TestLogDnsRoutingMissThrottled(t *testing.T) {
	var buf bytes.Buffer
	logger := log.StandardLogger()
	oldOut, oldFormatter := logger.Out, logger.Formatter
	logger.SetOutput(&buf)
	defer func() {
		logger.SetOutput(oldOut)
		logger.SetFormatter(oldFormatter)
	}()

	// Open the window regardless of what earlier tests logged.
	dnsRoutingMissLogAt.Store(time.Now().Add(-2 * time.Second).UnixNano())

	src := netip.MustParseAddrPort("192.168.16.129:44081")
	dst := netip.MustParseAddrPort("8.8.8.8:53")
	for range 1000 {
		logDnsRoutingMissThrottled(src, dst)
	}

	if got := strings.Count(buf.String(), "\n"); got != 1 {
		t.Fatalf("1000 misses in one window must log exactly once, got %d lines: %q", got, buf.String())
	}
}
