/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"net/netip"
	"testing"
)

func TestCouldBeIP(t *testing.T) {
	cases := []struct {
		in   string
		want bool
	}{
		{"", false},
		{"1.2.3.4", true},
		{"2606:4700:20::681a:d1f", true},
		{"::ffff:1.2.3.4", true},
		{"abc.com", false},      // non-hex letter
		{"beef.cafe", true},     // hex-only hostname — still passes the gate
		{"BEEF.CAFE", true},     // uppercase hex
		{"bad host", false},     // space
		{"1.2.3.999", true},     // charset passes; ParseAddr rejects later
		{"example.com.", false}, // trailing dot is not an IP char
		{"café.com", false},     // multi-byte rune
	}
	for _, c := range cases {
		if got := couldBeIP(c.in); got != c.want {
			t.Errorf("couldBeIP(%q) = %v, want %v", c.in, got, c.want)
		}
	}
}

func TestChooseDialTarget(t *testing.T) {
	dst4 := netip.MustParseAddrPort("93.184.216.34:443")
	dst6 := netip.MustParseAddrPort("[2606:4700:20::681a:d1f]:443")

	cases := []struct {
		name       string
		dst        netip.AddrPort
		domain     string
		override   bool
		wantTarget string
		wantDialIP bool
	}{
		{"no override hostname", dst4, "abc.xyz.com", false, dst4.String(), true},
		{"no override ip", dst4, "1.2.3.4", false, dst4.String(), true},
		{"empty domain", dst4, "", true, dst4.String(), true},
		{"hostname dials by name", dst4, "abc.xyz.com", true, "abc.xyz.com:443", false},
		{"fqdn-ish with digits", dst4, "1-2.example.com", true, "1-2.example.com:443", false},
		{"ipv4 literal falls back to dst", dst4, "1.2.3.4", true, dst4.String(), true},
		{
			// Regression: the old hand-rolled classifier returned bare IPv6
			// literals without appending a port ("missing port in address").
			"ipv6 literal falls back to dst",
			dst6, "2606:4700:20::681a:d1f", true, dst6.String(), true,
		},
		{
			// Regression: "beef.cafe" was misclassified as an IPv4 literal
			// (hasAlpha only counted g-z), forcing strict IP-version dialer
			// selection for a hostname.
			"hex-only hostname dials by name",
			dst4, "beef.cafe", true, "beef.cafe:443", false,
		},
		{"uppercase hostname dials by name", dst4, "ABC.COM", true, "ABC.COM:443", false},
		{"ipv4-mapped literal falls back to dst", dst4, "::ffff:1.2.3.4", true, dst4.String(), true},
		{"invalid ip-like garbage dials by name", dst4, "111.222.333.444", true, "111.222.333.444:443", false},
		{"garbage with colon dials by name", dst4, "bad:host", true, "bad:host:443", false},
	}
	for _, c := range cases {
		gotTarget, gotDialIP := chooseDialTarget(c.dst, c.domain, c.override)
		if gotTarget != c.wantTarget || gotDialIP != c.wantDialIP {
			t.Errorf("%s: chooseDialTarget(%v, %q, %v) = (%q, %v), want (%q, %v)",
				c.name, c.dst, c.domain, c.override, gotTarget, gotDialIP, c.wantTarget, c.wantDialIP)
		}
	}
}
