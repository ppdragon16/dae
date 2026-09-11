/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package config

import (
	"strings"
	"testing"
	"time"

	"github.com/daeuniverse/dae/pkg/config_parser"
)

func TestGlobalCheckIntervalRejectsNonPositive(t *testing.T) {
	for _, section := range []string{`
global {
  check_interval: 0s
}
routing {
  fallback: direct
}
`, `
global {
  check_interval: -5s
}
routing {
  fallback: direct
}
`} {
		sections, err := config_parser.Parse(section)
		if err != nil {
			t.Fatalf("parse: %v", err)
		}

		_, err = New(sections)
		if err == nil || !strings.Contains(err.Error(), "check_interval") {
			t.Fatalf("expected check_interval error, got %v", err)
		}
	}
}

func TestPatchCheckInterval(t *testing.T) {
	params := &Config{
		Global: Global{CheckInterval: 30 * time.Second},
		Group: []Group{
			{Name: "a"},
			{Name: "b", CheckInterval: 10 * time.Second},
		},
	}
	if err := patchCheckInterval(params); err != nil {
		t.Fatalf("valid config rejected: %v", err)
	}

	params.Group[0].CheckInterval = -1 * time.Second
	err := patchCheckInterval(params)
	if err == nil || !strings.Contains(err.Error(), "check_interval") {
		t.Fatalf("expected negative group check_interval error, got %v", err)
	}

	params = &Config{}
	if err := patchCheckInterval(params); err == nil || !strings.Contains(err.Error(), "check_interval") {
		t.Fatalf("expected non-positive global check_interval error, got %v", err)
	}
}

// TestMissingOptionalSectionsStillApplyDefaults pins the absent-section
// contract: a config that omits an optional section must decode that section
// from an empty section so its documented `default:` tags apply, instead of
// silently keeping the Go zero values. (Port of kdae a4cffe92, P3-1.)
func TestMissingOptionalSectionsStillApplyDefaults(t *testing.T) {
	sections, err := config_parser.Parse(`
global {}
routing {
  fallback: direct
}
`)
	if err != nil {
		t.Fatal(err)
	}
	conf, err := New(sections)
	if err != nil {
		t.Fatal(err)
	}

	if conf.Dns.MinSniffingTtl != 24*time.Hour {
		t.Fatalf("missing dns section: min_sniffing_ttl = %v, want the documented default 24h", conf.Dns.MinSniffingTtl)
	}
	if !conf.Dns.EnableCache {
		t.Fatal("missing dns section: enable_cache must take the documented default true")
	}
	if conf.Dns.UdpPoolSize != 10 {
		t.Fatalf("missing dns section: udp_pool_size = %d, want the documented default 10", conf.Dns.UdpPoolSize)
	}
	if conf.Global.TproxyPort != 12345 {
		t.Fatalf("missing global params: tproxy_port = %d, want the documented default 12345", conf.Global.TproxyPort)
	}
	if conf.Group != nil || conf.Subscription != nil || conf.Node != nil {
		t.Fatalf("absent list sections must decode to nil, got group=%v subscription=%v node=%v", conf.Group, conf.Subscription, conf.Node)
	}

	// An explicit value must still win over the default; the decoder must not
	// remap it.
	sections, err = config_parser.Parse(`
global {
  tproxy_port: 12346
}
dns {
  min_sniffing_ttl: 0
}
routing {
  fallback: direct
}
`)
	if err != nil {
		t.Fatal(err)
	}
	conf, err = New(sections)
	if err != nil {
		t.Fatal(err)
	}
	if conf.Global.TproxyPort != 12346 {
		t.Fatalf("explicit tproxy_port overwritten: got %d", conf.Global.TproxyPort)
	}
	if conf.Dns.MinSniffingTtl != 0 {
		t.Fatalf("explicit min_sniffing_ttl overwritten: got %v", conf.Dns.MinSniffingTtl)
	}
}
