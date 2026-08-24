/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package cmd

import (
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"testing"

	"github.com/daeuniverse/dae/common/consts"
	"github.com/spf13/cobra"
)

// TestReloadUpdateFallbackResetsProgressMarker locks down the regression where
// the reload/update commands, upon detecting an "old daemon" (one that does not
// acknowledge the *Send marker within the timeout), printed "OK" but left the
// *Send code in the signal progress file. Every subsequent command then read
// that stale *Send code and reported "another operation is in progress".
//
// The test mirrors the real chain: a live subprocess standing in for the
// daemon, a real signal, and the real command Run functions against a temp
// progress file. It asserts that after a fallback the marker is reset to
// ReloadDone (the idle state), so a following command is not blocked.
func TestReloadUpdateFallbackResetsProgressMarker(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires root so internal.AutoSu is a no-op")
	}

	cases := []struct {
		name     string
		run      func(cmd *cobra.Command, args []string)
		sendCode byte
	}{
		{"reload", reloadCmd.Run, consts.ReloadSend},
		{"update-sub", updateSubCmd.Run, consts.UpdateSubSend},
		{"update-dns", updateDnsCmd.Run, consts.UpdateDnsSend},
		{"update-routing", updateRoutingCmd.Run, consts.UpdateRoutingSend},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()

			// Redirect the package-level paths so the test never touches
			// /var/run. Restore on return.
			origPid, origProgress := PidFilePath, SignalProgressFilePath
			PidFilePath = filepath.Join(dir, "dae.pid")
			SignalProgressFilePath = filepath.Join(dir, "dae.progress")
			defer func() {
				PidFilePath, SignalProgressFilePath = origPid, origProgress
			}()

			// Fake "old daemon": a process that ignores both SIGHUP and
			// SIGUSR1, so the *Send marker is never overwritten.
			daemon := exec.Command("bash", "-c", "trap '' HUP USR1; while :; do sleep 1; done")
			if err := daemon.Start(); err != nil {
				t.Fatalf("start fake daemon: %v", err)
			}
			defer func() {
				_ = daemon.Process.Kill()
				_ = daemon.Wait()
			}()

			if err := os.WriteFile(PidFilePath, []byte(strconv.Itoa(daemon.Process.Pid)), 0644); err != nil {
				t.Fatalf("write pid file: %v", err)
			}
			// The daemon writes ReloadDone on startup.
			if err := os.WriteFile(SignalProgressFilePath, []byte{consts.ReloadDone}, 0644); err != nil {
				t.Fatalf("write progress file: %v", err)
			}

			// Trigger the fallback path.
			tc.run(nil, nil)

			code, _, err := readSignalProgressFile()
			if err != nil {
				t.Fatalf("read progress file after fallback: %v", err)
			}
			if code == tc.sendCode {
				t.Fatalf("fallback left stale %q marker; a subsequent command would report 'another operation is in progress'", code)
			}
			if code != consts.ReloadDone {
				t.Fatalf("expected marker reset to ReloadDone (%q), got %q", consts.ReloadDone, code)
			}
		})
	}
}
