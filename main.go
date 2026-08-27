//go:build linux

/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package main

import (
	"net/http"
	"os"
	"runtime"
	"strconv"
	"time"

	"github.com/daeuniverse/dae/cmd"
)

func main() {
	// Allow precise heap profiling via env var. Default is 512KB sampling,
	// which amplifies small one-shot allocations into ~512KB noise. Set
	// DAE_MEM_PROFILE_RATE=1 for exact sampling, or e.g. 8192 for 8KB.
	if v := os.Getenv("DAE_MEM_PROFILE_RATE"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			runtime.MemProfileRate = n
		}
	}

	http.DefaultClient.Timeout = 30 * time.Second
	if err := cmd.Execute(); err != nil {
		os.Exit(1)
	}
	os.Exit(0)
}
