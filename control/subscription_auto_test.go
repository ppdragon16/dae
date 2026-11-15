/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"testing"

	"github.com/daeuniverse/dae/config"
)

func TestSubStateHash(t *testing.T) {
	c := &ControlPlane{}
	base := map[string][]string{
		"lxy": {"node-a", "node-b"},
		"evo": {"node-c"},
	}
	groups := []config.Group{{Name: "mix"}}

	same := map[string][]string{
		"evo": {"node-c"},
		// Order within and across tags must not matter.
		"lxy": {"node-b", "node-a"},
	}
	if c.subStateHash(base, groups) != c.subStateHash(same, groups) {
		t.Fatal("reordered identical state produced different canonical forms")
	}

	changed := []struct {
		name   string
		state  map[string][]string
		groups []config.Group
	}{
		{"node link replaced", map[string][]string{
			"lxy": {"node-a", "node-b2"},
			"evo": {"node-c"},
		}, groups},
		{"node added", map[string][]string{
			"lxy": {"node-a", "node-b", "node-d"},
			"evo": {"node-c"},
		}, groups},
		{"node removed", map[string][]string{
			"lxy": {"node-a"},
			"evo": {"node-c"},
		}, groups},
		{"tag renamed", map[string][]string{
			"lxy2": {"node-a", "node-b"},
			"evo":  {"node-c"},
		}, groups},
		{"tag dropped", map[string][]string{
			"lxy": {"node-a", "node-b"},
		}, groups},
	}
	for _, tc := range changed {
		if c.subStateHash(tc.state, tc.groups) == c.subStateHash(base, groups) {
			t.Fatalf("%s: canonical form did not change", tc.name)
		}
	}

	// A group-config change (filter edit) must also change the canonical form
	// even when the node links are identical.
	groupsWithFilter := []config.Group{{Name: "mix"}, {Name: "us"}}
	if c.subStateHash(base, groupsWithFilter) == c.subStateHash(base, groups) {
		t.Fatal("group change did not change the canonical form")
	}
}
