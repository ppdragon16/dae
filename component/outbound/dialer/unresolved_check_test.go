/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package dialer

import (
	"context"
	"errors"
	"net"
	"sync/atomic"
	"testing"
	"time"

	D "github.com/daeuniverse/outbound/dialer"
	"github.com/daeuniverse/outbound/netproxy"
)

// flakyProbeDialer accepts the transport but fails every probe while `failing`
// is set, so the initial-check give-up path can be driven without sockets.
type flakyProbeDialer struct {
	failing  atomic.Bool
	attempts atomic.Int32
}

func (f *flakyProbeDialer) Alive() bool       { return true }
func (f *flakyProbeDialer) Connect() error    { return nil }
func (f *flakyProbeDialer) Disconnect() error { return nil }

func (f *flakyProbeDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	f.attempts.Add(1)
	return nil, errors.New("probe: injected failure")
}

func (f *flakyProbeDialer) ListenPacket(ctx context.Context, address string) (net.PacketConn, error) {
	return nil, errors.New("probe: injected failure")
}

var _ netproxy.Dialer = (*flakyProbeDialer)(nil)

// recoverableNetDialer adds the Connect/Disconnect a not-alive dialer needs to
// be brought back by the check loop.
type recoverableNetDialer struct{ mockNetDialer }

func (r *recoverableNetDialer) Connect() error    { return nil }
func (r *recoverableNetDialer) Disconnect() error { return nil }

func waitForCondition(t *testing.T, timeout time.Duration, cond func() bool, msg string) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(2 * time.Millisecond)
	}
	t.Fatalf("timed out after %v: %s", timeout, msg)
}

// TestDialer_InitialCheckGiveUpKeepsRetrying pins the contract of the
// initial-check give-up path. It used to return with neither a ticker nor a
// loop running and without ever calling Update(false): a node that was merely
// unreachable during daemon startup (WAN not up yet, or its check server
// blocked) stayed disabled for the rest of the process lifetime, and a dialer
// that had been alive kept alive=true (which also skipped the recycle path's
// ResetLatency).
func TestDialer_InitialCheckGiveUpKeepsRetrying(t *testing.T) {
	oldInterval := initialCheckRetryInterval
	initialCheckRetryInterval = time.Millisecond
	t.Cleanup(func() { initialCheckRetryInterval = oldInterval })

	probe := &flakyProbeDialer{}
	probe.failing.Store(true)
	option := &GlobalOption{
		CheckDnsOptionRaw: CheckDnsOptionRaw{Raw: []string{"1.1.1.1:53"}},
		CheckInterval:     5 * time.Millisecond,
	}
	d := NewDialer(probe, option, &Property{Property: D.Property{Name: "flaky"}}, true)
	t.Cleanup(d.stopCheck)
	d.RegisterDialerGroup(&mockDialerGroup{id: 1})
	// Reproduce the dangerous case: this dialer was alive before the
	// re-activation, and now every probe fails.
	d.alive.Store(true)

	d.ActivateCheck()

	// The give-up must correct the liveness state instead of leaving the
	// stale alive=true behind.
	waitForCondition(t, 3*time.Second, func() bool { return !d.Alive() },
		"dialer stayed alive after the initial check gave up")

	// And it must leave a loop running that keeps probing, so the node can
	// recover without a reload.
	before := probe.attempts.Load()
	waitForCondition(t, 3*time.Second, func() bool { return probe.attempts.Load() > before },
		"no probe ran after the give-up: the dialer was left without a check loop")
}

// TestDialer_UnresolvedCheckLoopRecovers drives the unresolved loop directly
// with injected probe results: a failing round must mark the dialer
// not-alive, and the next successful round must revive it (and hand over to
// the steady-state loop).
func TestDialer_UnresolvedCheckLoopRecovers(t *testing.T) {
	d := NewDialer(&recoverableNetDialer{}, &GlobalOption{CheckInterval: 5 * time.Millisecond},
		&Property{Property: D.Property{Name: "recover"}}, true)
	t.Cleanup(d.stopCheck)
	d.RegisterDialerGroup(&mockDialerGroup{id: 1})
	d.alive.Store(true)

	var healthy atomic.Bool
	opt := &CheckOption{
		networkType: testNetType,
		CheckFunc: func() (bool, error) {
			if healthy.Load() {
				return true, nil
			}
			return false, errors.New("probe: injected failure")
		},
	}

	go d.runUnresolvedCheckLoop([]*CheckOption{opt})

	d.checkCh <- time.Now() // round 1: fails
	waitForCondition(t, 2*time.Second, func() bool { return !d.Alive() },
		"a failed round must mark the dialer not-alive")

	healthy.Store(true)
	d.checkCh <- time.Now() // round 2: succeeds
	waitForCondition(t, 2*time.Second, func() bool { return d.Alive() },
		"a successful round must revive the dialer")
}

// TestDialer_InitialCheckReportsProbeError pins the error plumbing the give-up
// handler relies on: runInitialCheck must return a nil opt *and* the probe
// error instead of a bare nil, so the liveness correction carries a reason.
func TestDialer_InitialCheckReportsProbeError(t *testing.T) {
	d := NewDialer(&recoverableNetDialer{}, &GlobalOption{CheckInterval: 5 * time.Millisecond},
		&Property{Property: D.Property{Name: "unreachable"}}, true)
	t.Cleanup(d.stopCheck)
	d.RegisterDialerGroup(&mockDialerGroup{id: 1})
	d.alive.Store(true)

	want := errors.New("probe: injected failure")
	opt := &CheckOption{
		networkType: testNetType,
		CheckFunc:   func() (bool, error) { return false, want },
	}

	gotOpt, err := d.runInitialCheck([]*CheckOption{opt})
	if gotOpt != nil {
		t.Fatalf("opt = %v, want nil", gotOpt)
	}
	if !errors.Is(err, want) {
		t.Fatalf("err = %v, want the probe error", err)
	}
}

// TestNotifyCheckRearmsAMissingCheckLoop pins the watchdog for the class of
// state this incident exposed: the dialer is marked activated but no check
// chain owns its context (the chain never started, or exited without
// re-arming). NotifyCheck used to push a tick into checkCh that nobody read,
// leaving the dialer dead until a reload; it must re-arm the chain instead.
func TestNotifyCheckRearmsAMissingCheckLoop(t *testing.T) {
	oldInterval := initialCheckRetryInterval
	initialCheckRetryInterval = time.Millisecond
	t.Cleanup(func() { initialCheckRetryInterval = oldInterval })

	probe := &flakyProbeDialer{}
	probe.failing.Store(true)
	d := NewDialer(probe, &GlobalOption{CheckInterval: 5 * time.Millisecond},
		&Property{Property: D.Property{Name: "missing-loop"}}, true)
	t.Cleanup(d.stopCheck)
	d.RegisterDialerGroup(&mockDialerGroup{id: 1})

	// The stuck state: activated, but nothing is running.
	d.checkActivated = true
	d.checkRunning.Store(false)
	before := d.checkCtx

	d.NotifyCheck()

	if d.checkCtx == before {
		t.Fatal("NotifyCheck did not re-arm the missing check chain")
	}
	if !d.checkActivated {
		t.Fatal("re-arming must leave the dialer activated")
	}
}

// TestCheckRunningTracksTheLoop pins the lifecycle flag the watchdog and the
// logs rely on: the unresolved-discovery loop marks the dialer as running while
// it owns the context, and the flag drops when stopCheck cancels it.
func TestCheckRunningTracksTheLoop(t *testing.T) {
	oldInterval := initialCheckRetryInterval
	initialCheckRetryInterval = time.Millisecond
	t.Cleanup(func() { initialCheckRetryInterval = oldInterval })

	d := NewDialer(&recoverableNetDialer{}, &GlobalOption{CheckInterval: time.Hour},
		&Property{Property: D.Property{Name: "flag"}}, true)
	t.Cleanup(d.stopCheck)
	d.RegisterDialerGroup(&mockDialerGroup{id: 1})
	d.alive.Store(true)

	var calls atomic.Int32
	opt := &CheckOption{
		networkType: testNetType,
		CheckFunc: func() (bool, error) {
			calls.Add(1)
			return false, errors.New("probe: injected failure")
		},
	}

	d.onInitialCheckUnresolved(errors.New("no usable network type"), []*CheckOption{opt})
	if !d.checkRunning.Load() {
		t.Fatal("the unresolved-discovery loop must mark the dialer as running")
	}

	d.checkCh <- time.Now()
	waitForCondition(t, 2*time.Second, func() bool { return calls.Load() > 0 },
		"the unresolved loop did not run a discovery round")
	if !d.checkRunning.Load() {
		t.Fatal("the flag must stay set while the loop keeps retrying")
	}

	d.stopCheck()
	waitForCondition(t, 2*time.Second, func() bool { return !d.checkRunning.Load() },
		"the flag must drop once the loop is cancelled")
}
