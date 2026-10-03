/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package dialer

import (
	"bytes"
	"context"
	"errors"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/daeuniverse/dae/common/netutils"
	D "github.com/daeuniverse/outbound/dialer"
	"github.com/daeuniverse/outbound/netproxy"
	"github.com/daeuniverse/outbound/protocol/direct"
	log "github.com/sirupsen/logrus"
)

// swapDirect replaces the package-level direct dialer, which is where
// direct.ResolveHost reads the dae mark and fallback_resolver from.
func swapDirect(t *testing.T, d netproxy.Dialer) {
	t.Helper()
	old := direct.Direct
	direct.Direct = d
	t.Cleanup(func() { direct.Direct = old })
}

// foreignDialer is not a *directDialer, so direct.ResolveHost rejects it. It
// makes "did this path go through the direct policy?" observable without DNS.
type foreignDialer struct{ netproxy.Dialer }

func TestResolveCheckHostGoesThroughDirectPolicy(t *testing.T) {
	swapDirect(t, foreignDialer{})

	_, err := resolveCheckHost("node.example.com")
	if err == nil {
		t.Fatal("expected the direct policy to be consulted for a hostname")
	}
	if !strings.Contains(err.Error(), "not a direct dialer") {
		t.Fatalf("expected the direct policy's error, got %v", err)
	}
}

func TestResolveCheckHostSkipsLookupForLiteral(t *testing.T) {
	// A literal must be answered before the policy is consulted, which this
	// dialer makes observable by failing every lookup.
	swapDirect(t, foreignDialer{})

	ip46, err := resolveCheckHost("2001:4860:4860::8888")
	if err != nil {
		t.Fatalf("resolveCheckHost: %v", err)
	}
	if want := netip.MustParseAddr("2001:4860:4860::8888"); ip46.Ip6 != want {
		t.Errorf("expected %v, got %v", want, ip46.Ip6)
	}

	ip46, err = resolveCheckHost("8.8.8.8")
	if err != nil {
		t.Fatalf("resolveCheckHost: %v", err)
	}
	if want := netip.MustParseAddr("8.8.8.8"); ip46.Ip4 != want {
		t.Errorf("expected %v, got %v", want, ip46.Ip4)
	}
}

// TestResolveCheckHostAppliesDeadline covers the bound: the deadline is handed
// to the resolver, so a lookup that never answers fails the caller that is
// building the dialer set instead of stalling it. The resolver is passed in
// because the system resolver cannot be blackholed from a test.
func TestResolveCheckHostAppliesDeadline(t *testing.T) {
	oldTimeout := checkHostResolveTimeout
	checkHostResolveTimeout = 200 * time.Millisecond
	t.Cleanup(func() { checkHostResolveTimeout = oldTimeout })

	var gotDeadline time.Duration
	hang := func(ctx context.Context, host string) ([]string, error) {
		if deadline, ok := ctx.Deadline(); ok {
			gotDeadline = time.Until(deadline)
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(2 * time.Second):
			// Watchdog: an unbounded context would hang the test otherwise.
			return nil, errors.New("lookup was not bounded by a deadline")
		}
	}

	_, err := resolveCheckHostWith(hang, "race-probe.invalid")
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("expected context.DeadlineExceeded, got %v", err)
	}
	if gotDeadline <= 0 || gotDeadline > checkHostResolveTimeout {
		t.Fatalf("expected a deadline within %v, got %v", checkHostResolveTimeout, gotDeadline)
	}
}

// TestResolveCheckHostDeadlineFailurePath covers the error a caller sees when
// the lookup runs into that deadline.
func TestResolveCheckHostDeadlineFailurePath(t *testing.T) {
	oldTimeout := checkHostResolveTimeout
	checkHostResolveTimeout = 20 * time.Millisecond
	t.Cleanup(func() { checkHostResolveTimeout = oldTimeout })

	start := time.Now()
	_, err := resolveCheckHostWith(func(ctx context.Context, _ string) ([]string, error) {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(2 * time.Second):
			// Watchdog: an unbounded context would hang the test otherwise.
			return nil, errors.New("lookup was not bounded by a deadline")
		}
	}, "node.example.com")
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("expected context.DeadlineExceeded, got %v", err)
	}
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Fatalf("expected the lookup to stop at its budget, took %v", elapsed)
	}
}

// TestResolveCheckHostPassesAddressesThrough covers the success projection from
// the policy's answer to the address pair the option carries.
func TestResolveCheckHostPassesAddressesThrough(t *testing.T) {
	ip46, err := resolveCheckHostWith(func(_ context.Context, host string) ([]string, error) {
		if host != "node.example.com" {
			t.Errorf("expected node.example.com, got %q", host)
		}
		return []string{"4.4.4.4", "2001:db8::4"}, nil
	}, "node.example.com")
	if err != nil {
		t.Fatalf("resolveCheckHostWith: %v", err)
	}
	if want := netip.MustParseAddr("4.4.4.4"); ip46.Ip4 != want {
		t.Errorf("expected IPv4 %v, got %v", want, ip46.Ip4)
	}
	if want := netip.MustParseAddr("2001:db8::4"); ip46.Ip6 != want {
		t.Errorf("expected IPv6 %v, got %v", want, ip46.Ip6)
	}
}

// TestResolveCheckHostUsesSystemView covers a hostname the system view answers
// locally, through the real package-level policy.
func TestResolveCheckHostUsesSystemView(t *testing.T) {
	ip46, err := resolveCheckHost("localhost")
	if err != nil {
		t.Fatalf("resolveCheckHost: %v", err)
	}
	if want := netip.MustParseAddr("127.0.0.1"); ip46.Ip4 != want {
		t.Fatalf("expected %v first, got %v (ip6 %v)", want, ip46.Ip4, ip46.Ip6)
	}
}

// TestParseCheckDnsOptionResolvesHostname covers the udp_check_dns hostname
// form end to end, through the same policy a dial uses.
func TestParseCheckDnsOptionResolvesHostname(t *testing.T) {
	opt, err := ParseCheckDnsOption([]string{"localhost:53"})
	if err != nil {
		t.Fatalf("ParseCheckDnsOption: %v", err)
	}
	if opt.DnsHost != "localhost" || opt.DnsPort != 53 {
		t.Errorf("expected localhost:53, got %v:%v", opt.DnsHost, opt.DnsPort)
	}
	if want := netip.MustParseAddr("127.0.0.1"); opt.Ip4 != want {
		t.Errorf("expected %v, got %v", want, opt.Ip4)
	}
}

// TestParseCheckDnsOptionAddressListNeedsNoLookup covers the default
// configuration: pinned addresses must parse even when resolution is
// impossible, which the failing dialer makes observable.
func TestParseCheckDnsOptionAddressListNeedsNoLookup(t *testing.T) {
	swapDirect(t, foreignDialer{})

	opt, err := ParseCheckDnsOption([]string{"dns.google:53", "8.8.8.8", "2001:4860:4860::8888"})
	if err != nil {
		t.Fatalf("ParseCheckDnsOption: %v", err)
	}
	if want := netip.MustParseAddr("8.8.8.8"); opt.Ip4 != want {
		t.Errorf("expected IPv4 %v, got %v", want, opt.Ip4)
	}
	if want := netip.MustParseAddr("2001:4860:4860::8888"); opt.Ip6 != want {
		t.Errorf("expected IPv6 %v, got %v", want, opt.Ip6)
	}
}

func TestParseTcpCheckOptionAddressListNeedsNoLookup(t *testing.T) {
	swapDirect(t, foreignDialer{})

	opt, err := ParseTcpCheckOption([]string{"http://example.com/generate_204", "8.8.8.8", "2001:4860:4860::8888"}, "GET")
	if err != nil {
		t.Fatalf("ParseTcpCheckOption: %v", err)
	}
	if want := netip.MustParseAddr("8.8.8.8"); opt.Ip46.Ip4 != want {
		t.Errorf("expected IPv4 %v, got %v", want, opt.Ip46.Ip4)
	}
}

// TestIp46FromStrings covers the projection from resolved strings to the
// address pair a check option carries.
func TestIp46FromStrings(t *testing.T) {
	got := netutils.Ip46FromStrings([]string{"not-an-ip", "2001:db8::4", "4.4.4.4", "2001:db8::5", "5.5.5.5"})
	if want := netip.MustParseAddr("4.4.4.4"); got.Ip4 != want {
		t.Errorf("expected IPv4 %v, got %v", want, got.Ip4)
	}
	if want := netip.MustParseAddr("2001:db8::4"); got.Ip6 != want {
		t.Errorf("expected the first IPv6 %v, got %v", want, got.Ip6)
	}
	if empty := netutils.Ip46FromStrings(nil); empty.IsValid() {
		t.Errorf("expected an invalid Ip46 for no addresses, got %v", empty)
	}
}

// TestCheckDnsOptionRawErrorNamesConfigKey covers the error text: a bad
// udp_check_dns used to be reported as a tcp_check_url failure.
func TestCheckDnsOptionRawErrorNamesConfigKey(t *testing.T) {
	raw := &CheckDnsOptionRaw{Raw: []string{"dns.google"}}

	_, err := raw.Option()
	if err == nil {
		t.Fatal("expected an error for a missing port")
	}
	if !strings.Contains(err.Error(), "udp_check_dns") {
		t.Errorf("expected the config key in the error, got %q", err)
	}
	if strings.Contains(err.Error(), "tcp_check_url") {
		t.Errorf("error still blames tcp_check_url: %q", err)
	}
}

// TestCreateCheckOptionsReportsParseFailure covers the degraded path: a bad
// udp_check_dns still yields the four probes, but the reason must be logged
// instead of leaving the node to look unreachable.
func TestCreateCheckOptionsReportsParseFailure(t *testing.T) {
	d := NewDialer(&mockNetDialer{},
		&GlobalOption{CheckDnsOptionRaw: CheckDnsOptionRaw{Raw: []string{"not-a-host-port"}}},
		&Property{Property: D.Property{Name: "mock"}}, false)

	var buf bytes.Buffer
	oldOut := log.StandardLogger().Out
	oldLevel := log.GetLevel()
	log.SetOutput(&buf)
	log.SetLevel(log.WarnLevel)
	t.Cleanup(func() {
		log.SetOutput(oldOut)
		log.SetLevel(oldLevel)
	})

	opts := d.createCheckOptions()
	if len(opts) != 4 {
		t.Fatalf("expected the four probes to be built anyway, got %d", len(opts))
	}
	logged := buf.String()
	if !strings.Contains(logged, "udp_check_dns") {
		t.Errorf("expected the parse failure to be logged, got %q", logged)
	}
	if !strings.Contains(logged, "not-a-host-port") {
		t.Errorf("expected the offending value in the log, got %q", logged)
	}
}
