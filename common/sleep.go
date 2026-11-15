/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package common

import (
	"time"
)

// SleepOrDone waits d or until done is closed. It reports whether the full
// duration elapsed; false means done was closed first.
//
// The timer is stopped on exit, so a long duration never pins its runtime
// timer past the wait, and the done branch keeps the calling goroutine
// responsive to shutdown.
//
// Pass the returned timer back on the next call to reuse it across rounds;
// pass nil to start with a fresh one. Reuse is safe because this targets
// Go 1.23+, where Timer.Reset drains the channel, so re-arming a stopped
// timer cannot deliver a stale fire.
func SleepOrDone(done <-chan struct{}, d time.Duration, t *time.Timer) (*time.Timer, bool) {
	if t == nil {
		t = time.NewTimer(d)
	} else {
		t.Reset(d)
	}
	defer t.Stop()
	select {
	case <-done:
		return t, false
	case <-t.C:
		return t, true
	}
}
