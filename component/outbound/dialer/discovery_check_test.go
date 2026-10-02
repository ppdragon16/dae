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
	probe := &flakyProbeDialer{}
	probe.failing.Store(true)
	option := &GlobalOption{
		CheckDnsOptionRaw: CheckDnsOptionRaw{Raw: []string{"1.1.1.1:53"}},
		CheckInterval:     5 * time.Millisecond,
	}
	d := NewDialer(probe, option, &Property{Property: D.Property{Name: "flaky"}}, true)
	d.checkRetryInterval = time.Millisecond
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

// TestDialer_DiscoveryRecovers drives the merged check loop with injected
// probe results: a failing round must mark the dialer not-alive, and a later
// successful round must revive it and enter steady state.
func TestDialer_DiscoveryRecovers(t *testing.T) {
	d := NewDialer(&recoverableNetDialer{}, &GlobalOption{CheckInterval: 5 * time.Millisecond},
		&Property{Property: D.Property{Name: "recover"}}, true)
	d.checkRetryInterval = time.Millisecond
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

	go d.runCheckLoop(d.checkCtx, []*CheckOption{opt})

	// Discovery keeps failing: the dialer must be corrected to not-alive.
	waitForCondition(t, 2*time.Second, func() bool { return !d.Alive() },
		"a failed discovery round must mark the dialer not-alive")

	// The same goroutine must pick the network type up once it works.
	healthy.Store(true)
	waitForCondition(t, 2*time.Second, func() bool { return d.Alive() },
		"a successful discovery round must revive the dialer")
}

// TestDialer_DiscoveryRetriesArePaced pins the no-storm property that the old
// two-loop handover broke: while discovery keeps failing, retries are paced by
// checkRetryInterval and data-path nudges (NotifyCheck, which fires on
// every failed relay) cannot accelerate them into a probe storm.
func TestDialer_DiscoveryRetriesArePaced(t *testing.T) {
	const interval = 40 * time.Millisecond

	var probes atomic.Int32
	opt := &CheckOption{
		networkType: testNetType,
		CheckFunc: func() (bool, error) {
			probes.Add(1)
			return false, errors.New("probe: injected failure")
		},
	}

	d := NewDialer(&recoverableNetDialer{}, &GlobalOption{CheckInterval: time.Hour},
		&Property{Property: D.Property{Name: "paced"}}, true)
	d.checkRetryInterval = interval
	t.Cleanup(d.stopCheck)
	d.RegisterDialerGroup(&mockDialerGroup{id: 1})

	go d.runCheckLoop(d.checkCtx, []*CheckOption{opt})

	// Hammer the data path the way a burst of failing connections would.
	deadline := time.Now().Add(400 * time.Millisecond)
	for time.Now().Before(deadline) {
		d.NotifyCheck()
		time.Sleep(time.Millisecond)
	}
	// ~10 rounds fit in 400ms at 40ms pacing; anything close to the nudge rate
	// (hundreds) means discovery is spinning on checkCh again.
	if got := probes.Load(); got > 20 {
		t.Fatalf("discovery ran %d probes in 400ms with a %v retry interval: retries are not paced", got, interval)
	}
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
