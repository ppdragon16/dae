/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package common

import "testing"

func TestEnsureFileInSubDir(t *testing.T) {
	// A legitimate sibling whose name merely starts with dots must not be
	// rejected by a naive ".." prefix check.
	if err := EnsureFileInSubDir("/tmp/sub/...hidden", "/tmp/sub"); err != nil {
		t.Fatalf("legitimate sibling rejected: %v", err)
	}
	if err := EnsureFileInSubDir("/tmp/sub/file", "/tmp/sub"); err != nil {
		t.Fatalf("in-scope file rejected: %v", err)
	}
	if err := EnsureFileInSubDir("/tmp/other/file", "/tmp/sub"); err == nil {
		t.Fatal("out-of-scope file not rejected")
	}
}
