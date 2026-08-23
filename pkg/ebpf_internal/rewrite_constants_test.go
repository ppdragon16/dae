// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>

package internal

import (
	"errors"
	"strings"
	"testing"

	"github.com/cilium/ebpf"
)

func newSpecWithVariables(vars map[string]*ebpf.VariableSpec) *ebpf.CollectionSpec {
	return &ebpf.CollectionSpec{Variables: vars}
}

func TestRewriteConstantsSet(t *testing.T) {
	spec := newSpecWithVariables(map[string]*ebpf.VariableSpec{
		"foo": {Name: "foo", SectionName: ".rodata"},
	})
	if err := RewriteConstants(spec, map[string]interface{}{"foo": uint32(42)}); err != nil {
		t.Fatalf("RewriteConstants returned error: %v", err)
	}
	var got uint32
	if err := spec.Variables["foo"].Get(&got); err != nil {
		t.Fatalf("Get returned error: %v", err)
	}
	if got != 42 {
		t.Fatalf("expected 42, got %d", got)
	}
}

func TestRewriteConstantsMissing(t *testing.T) {
	spec := newSpecWithVariables(map[string]*ebpf.VariableSpec{
		"foo": {Name: "foo", SectionName: ".rodata"},
	})
	err := RewriteConstants(spec, map[string]interface{}{"foo": uint32(1), "bar": uint32(2), "baz": uint32(3)})
	if err == nil {
		t.Fatal("expected error for missing constants, got nil")
	}
	var m *MissingConstantsError
	if !errors.As(err, &m) {
		t.Fatalf("expected error to wrap *MissingConstantsError, got: %v", err)
	}
	msg := err.Error()
	if !strings.Contains(msg, "some constants are missing from .rodata") {
		t.Fatalf("unexpected error message: %v", err)
	}
	if len(m.Constants) != 2 {
		t.Fatalf("expected 2 missing constants, got %v", m.Constants)
	}
	// Map iteration order is non-deterministic; check set membership.
	seen := map[string]bool{}
	for _, c := range m.Constants {
		seen[c] = true
	}
	if !seen["bar"] || !seen["baz"] {
		t.Fatalf("expected missing constants {bar, baz}, got %v", m.Constants)
	}
}

func TestRewriteConstantsNotConstant(t *testing.T) {
	spec := newSpecWithVariables(map[string]*ebpf.VariableSpec{
		"foo": {Name: "foo", SectionName: ".data"},
	})
	err := RewriteConstants(spec, map[string]interface{}{"foo": 1})
	if err == nil {
		t.Fatal("expected error for non-constant variable, got nil")
	}
	if !strings.Contains(err.Error(), "is not a constant") {
		t.Fatalf("unexpected error message: %v", err)
	}
}
