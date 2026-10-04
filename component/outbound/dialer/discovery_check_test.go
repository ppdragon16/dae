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

	"github.com/daeuniverse/dae/common"
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

// TestDialer_SteadyStateFailureReDiscovers pins the recovery path: when the
// network type steady state is checking fails for good, the loop re-runs
// discovery, which refreshes the support matrix and picks a type that still
// works. Without it the dialer kept re-probing the dead type forever and the
// node stayed excluded until a reload, even though another type was fine.
func TestDialer_SteadyStateFailureReDiscovers(t *testing.T) {
	d := NewDialer(&recoverableNetDialer{}, &GlobalOption{CheckInterval: time.Hour},
		&Property{Property: D.Property{Name: "rediscover"}}, true)
	t.Cleanup(d.stopCheck)
	d.RegisterDialerGroup(&mockDialerGroup{id: 1})
	// Drive the retry budget fast: the assertion is about what happens after it
	// is exhausted, not about the schedule itself.
	d.checkRetryInterval = time.Millisecond

	var tcpHealthy atomic.Bool
	tcpHealthy.Store(true)
	optTCP := &CheckOption{
		networkType: common.NETWORK_TCP4,
		CheckFunc: func() (bool, error) {
			if tcpHealthy.Load() {
				return true, nil
			}
			return false, context.DeadlineExceeded
		},
	}
	optUDP := &CheckOption{
		networkType: common.NETWORK_UDP4,
		CheckFunc:   func() (bool, error) { return true, nil },
	}

	go d.runCheckLoopWith(d.checkCtx, []*CheckOption{optTCP, optUDP}, 3, time.Millisecond)
	waitForCondition(t, 2*time.Second, func() bool { return d.Alive() },
		"discovery must mark the dialer alive")

	// The type discovery picked (the first supported one) dies; the other works.
	tcpHealthy.Store(false)
	d.checkCh <- time.Now()

	tcpIdx := common.NetworkTypeToIndex(common.NETWORK_TCP4)
	udpIdx := common.NetworkTypeToIndex(common.NETWORK_UDP4)
	waitForCondition(t, 3*time.Second, func() bool {
		return !d.Supported(tcpIdx)
	}, "the dead type must be dropped from the support matrix after rediscovery")
	if !d.Supported(udpIdx) {
		t.Fatal("the type that still works must stay supported")
	}
	waitForCondition(t, 3*time.Second, func() bool { return d.Alive() },
		"the dialer must come back alive on the type that still works")
}

// TestDialer_TransientProbeFailureIsAbsorbed pins the other half of the
// contract: a single failed probe inside one cycle must NOT be treated as the
// type being dead, so no rediscovery happens and the dialer stays alive.
func TestDialer_TransientProbeFailureIsAbsorbed(t *testing.T) {
	d := NewDialer(&recoverableNetDialer{}, &GlobalOption{CheckInterval: time.Hour},
		&Property{Property: D.Property{Name: "blip"}}, true)
	t.Cleanup(d.stopCheck)
	d.RegisterDialerGroup(&mockDialerGroup{id: 1})
	d.checkRetryInterval = time.Millisecond

	// Calls 1 and 2 are discovery's cold + warm probe; call 3 is the steady
	// cycle's first probe and fails; call 4 (the retry) succeeds.
	var calls atomic.Int32
	optTCP := &CheckOption{
		networkType: common.NETWORK_TCP4,
		CheckFunc: func() (bool, error) {
			if calls.Add(1) == 3 {
				return false, context.DeadlineExceeded
			}
			return true, nil
		},
	}

	go d.runCheckLoopWith(d.checkCtx, []*CheckOption{optTCP}, 3, time.Millisecond)
	waitForCondition(t, 2*time.Second, func() bool { return d.Alive() },
		"discovery must mark the dialer alive")

	d.checkCh <- time.Now()
	waitForCondition(t, 2*time.Second, func() bool { return calls.Load() >= 4 },
		"the steady cycle did not retry after its failed probe")
	// Settle. Exactly four probes must have happened: two for discovery (cold +
	// warm) plus the failed probe and its retry. A rediscovery round would add
	// two more, which is what this assertion rules out — otherwise the test
	// could not tell "the blip was absorbed" from "the dialer recovered by
	// re-running discovery".
	time.Sleep(80 * time.Millisecond)
	if got := calls.Load(); got != 4 {
		t.Fatalf("expected 4 probes (discovery cold+warm, one failure, one retry), got %d: the blip triggered a rediscovery round", got)
	}
	if !d.Alive() {
		t.Fatal("a transient probe failure flipped the dialer not-alive")
	}
	if !d.Supported(common.NetworkTypeToIndex(common.NETWORK_TCP4)) {
		t.Fatal("a transient probe failure must not drop the type from the support matrix")
	}
}

// deadConnectDialer fails Connect: the discovery round then errors out before
// any probe runs, which is exactly the path that used to wipe the support
// matrix via supported.Store(0).
type deadConnectDialer struct{ mockNetDialer }

func (d *deadConnectDialer) Connect() error    { return errors.New("connection refused") }
func (d *deadConnectDialer) Disconnect() error { return nil }

// TestDialer_InitialCheckFailureKeepsSupportMatrix pins the in-place support
// update: a discovery round that fails before probing (connect failure) must
// keep the previous round's support matrix. Wiping it at entry left the dialer
// unsupported for every type during re-discovery, so flows of all types lost
// the node for the whole probing window.
func TestDialer_InitialCheckFailureKeepsSupportMatrix(t *testing.T) {
	d := NewDialer(&deadConnectDialer{}, &GlobalOption{CheckInterval: time.Hour},
		&Property{Property: D.Property{Name: "keep-matrix"}}, true)
	t.Cleanup(d.stopCheck)
	d.RegisterDialerGroup(&mockDialerGroup{id: 1})

	tcpIdx := common.NetworkTypeToIndex(testNetType)
	d.setSupportedBit(tcpIdx, true)
	d.Update(false, 0, testNetType, nil) // not alive -> the round connects first

	opt := &CheckOption{
		networkType: testNetType,
		CheckFunc: func() (bool, error) {
			t.Fatal("probes must not run when the connect already failed")
			return false, nil
		},
	}
	if _, err := d.runInitialCheck([]*CheckOption{opt}); err == nil {
		t.Fatal("expected the discovery round to fail on connect")
	}
	if !d.Supported(tcpIdx) {
		t.Fatal("a failed discovery round wiped the support matrix before probing")
	}
}
