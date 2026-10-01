/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package assets

import (
	"fmt"
	"strings"
	"testing"
)

// TestGetLocationAssetNamesTheEnvironmentVariable pins the not-found error: it
// must say whether this process saw DAE_LOCATION_ASSET, because a value exported
// in an interactive shell never reaches a daemon started by systemd, and the
// directory must be listed exactly once (it used to be appended twice in this
// branch).
func TestGetLocationAssetNamesTheEnvironmentVariable(t *testing.T) {
	externDir := t.TempDir()
	envDir := t.TempDir()
	t.Setenv("DAE_LOCATION_ASSET", envDir)

	f := NewLocationFinder([]string{externDir})
	_, err := f.GetLocationAsset("missing.dat")
	if err == nil {
		t.Fatal("expected a not-found error")
	}
	msg := err.Error()
	if !strings.Contains(msg, fmt.Sprintf("DAE_LOCATION_ASSET=%q", envDir)) {
		t.Fatalf("error does not name DAE_LOCATION_ASSET: %v", err)
	}
	// The searched list is the bracketed part; every directory must appear in it
	// exactly once (the DAE_LOCATION_ASSET branch used to append externDirs
	// twice). The env dir legitimately appears a second time in the trailing
	// note that names the variable.
	open := strings.Index(msg, "[")
	closeIdx := strings.Index(msg, "]")
	if open < 0 || closeIdx < open {
		t.Fatalf("error does not list the searched directories: %v", err)
	}
	list := msg[open+1 : closeIdx]
	if got := strings.Count(list, envDir); got != 1 {
		t.Fatalf("DAE_LOCATION_ASSET directory appears %d times in the search list, want once: %v", got, err)
	}
	if got := strings.Count(list, externDir); got != 1 {
		t.Fatalf("external dir appears %d times in the search list, want once: %v", got, err)
	}
}

// TestGetLocationAssetSaysWhenTheVariableIsUnset covers the other half: the
// daemon's own environment is the only place the value is read from.
func TestGetLocationAssetSaysWhenTheVariableIsUnset(t *testing.T) {
	t.Setenv("DAE_LOCATION_ASSET", "")

	f := NewLocationFinder([]string{t.TempDir()})
	_, err := f.GetLocationAsset("missing.dat")
	if err == nil {
		t.Fatal("expected a not-found error")
	}
	if !strings.Contains(err.Error(), "DAE_LOCATION_ASSET is not set") {
		t.Fatalf("error does not report the unset variable: %v", err)
	}
}
