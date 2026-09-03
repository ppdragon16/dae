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
