/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"errors"
	"net/netip"
	"slices"
	"strings"
	"testing"
)

func TestRoutingMatcherBuilderForEachStaleLpmSlot(t *testing.T) {
	tests := []struct {
		name           string
		previousCount  uint32
		currentCount   int
		wantIterations []uint32
	}{
		{name: "first activation leaves unused slots untouched", currentCount: 2},
		{name: "shrink visits only stale tail", previousCount: 4, currentCount: 2, wantIterations: []uint32{2, 3}},
		{name: "shrink to no tries visits every old slot", previousCount: 3, wantIterations: []uint32{0, 1, 2}},
		{name: "same size rebuild leaves unused slots untouched", previousCount: 2, currentCount: 2},
		{name: "growth leaves unused slots untouched", previousCount: 1, currentCount: 3},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			builder := &RoutingMatcherBuilder{
				bpf:               &bpfState{activeLpmTrieCount: tt.previousCount},
				simulatedLpmTries: make([][]netip.Prefix, tt.currentCount),
			}
			var iterations []uint32
			if err := builder.forEachStaleLpmSlot(func(i uint32) error {
				iterations = append(iterations, i)
				return nil
			}); err != nil {
				t.Fatal(err)
			}
			if !slices.Equal(iterations, tt.wantIterations) {
				t.Fatalf("iterations = %v, want %v", iterations, tt.wantIterations)
			}
		})
	}

	t.Run("callback failure stops iteration", func(t *testing.T) {
		builder := &RoutingMatcherBuilder{
			bpf:               &bpfState{activeLpmTrieCount: 5},
			simulatedLpmTries: make([][]netip.Prefix, 2),
		}
		callbackErr := errors.New("callback failed")
		var iterations []uint32
		err := builder.forEachStaleLpmSlot(func(i uint32) error {
			iterations = append(iterations, i)
			if i == 3 {
				return callbackErr
			}
			return nil
		})
		if !errors.Is(err, callbackErr) {
			t.Fatalf("error = %v, want wrapped callback error", err)
		}
		if !strings.Contains(err.Error(), "index 3") {
			t.Fatalf("error = %v, want failing slot index", err)
		}
		if want := []uint32{2, 3}; !slices.Equal(iterations, want) {
			t.Fatalf("iterations = %v, want %v", iterations, want)
		}
	})
}
