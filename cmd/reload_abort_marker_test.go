/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package cmd

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// TestCreateReloadAbortMarker pins the create contract: the marker exists after
// a successful call, and a failure (missing directory, here) is reported rather
// than swallowed -- the user asked for established connections to be aborted,
// and signalling without the marker silently drops that request. (Port of kdae
// 0760ccb4 / 3526cbfd.)
func TestCreateReloadAbortMarker(t *testing.T) {
	path := filepath.Join(t.TempDir(), "dae.abort")
	if err := createReloadAbortMarker(path); err != nil {
		t.Fatalf("createReloadAbortMarker() error = %v", err)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("marker missing after a successful create: %v", err)
	}

	missing := filepath.Join(t.TempDir(), "no-such-dir", "dae.abort")
	if err := createReloadAbortMarker(missing); err == nil {
		t.Fatal("createReloadAbortMarker() error = nil, want a missing-directory failure")
	}
}

// TestCleanupReloadAbortMarker pins the two cleanup rules: a marker this command
// created is removed and the original cause survives, while a marker it did not
// create (created == false) is left alone so an unrelated abort request is not
// silently dropped. (Port of kdae 3526cbfd.)
func TestCleanupReloadAbortMarker(t *testing.T) {
	path := filepath.Join(t.TempDir(), "dae.abort")
	if err := createReloadAbortMarker(path); err != nil {
		t.Fatal(err)
	}
	notDelivered := errors.New("signal was not delivered")
	if err := cleanupReloadAbortMarker(path, true, notDelivered); !errors.Is(err, notDelivered) {
		t.Fatalf("cleanup error = %v, want the original cause", err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("marker should be gone after cleanup, stat err = %v", err)
	}

	// A marker this command did not create must survive.
	foreign := filepath.Join(t.TempDir(), "dae.abort")
	if err := createReloadAbortMarker(foreign); err != nil {
		t.Fatal(err)
	}
	cause := errors.New("busy")
	if err := cleanupReloadAbortMarker(foreign, false, cause); !errors.Is(err, cause) {
		t.Fatalf("cleanup error = %v, want the cause unchanged", err)
	}
	if _, err := os.Stat(foreign); err != nil {
		t.Fatalf("a marker this command did not create must be left alone: %v", err)
	}
}
