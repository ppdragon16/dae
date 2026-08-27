/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package dialer

import (
	"context"
	"net"
	"reflect"
	"sync/atomic"
	"testing"
	"time"
	"unsafe"

	"github.com/daeuniverse/dae/common"
	"github.com/daeuniverse/dae/common/consts"
	D "github.com/daeuniverse/outbound/dialer"
	"github.com/daeuniverse/outbound/netproxy"
)

// mockDialerGroup satisfies DialerGroup for tests. The `id` field is unused
// at runtime but is needed to defeat the Go compiler's stack-slot reuse for
// adjacent zero-value local variables: without distinct non-zero fields, two
// `var g1, g2 mockDialerGroup` declarations would be observably aliased to
// the same address, which would silently merge g1 and g2 in interface-keyed
// maps. (See https://github.com/golang/go/issues/16962.)
type mockDialerGroup struct{ id int }

func (m *mockDialerGroup) NotifyStatusChange(*Dialer)       {}
func (m *mockDialerGroup) GetEmaAlpha() float64             { return 0.3 }
func (m *mockDialerGroup) GetTimeoutPenalty() time.Duration { return 0 }

// mockNetDialer is a minimal netproxy.Dialer whose Alive() always reports true.
type mockNetDialer struct{ netproxy.Dialer }

func (m *mockNetDialer) Alive() bool  { return true }
func (m *mockNetDialer) Name() string { return "mock" }
func (m *mockNetDialer) Dial(network, address string) (net.Conn, error) {
	return nil, nil
}
func (m *mockNetDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	return nil, nil
}
func (m *mockNetDialer) ListenPacket(ctx context.Context, address string) (net.PacketConn, error) {
	return nil, nil
}

func newTestDialer(t *testing.T) *Dialer {
	t.Helper()
	option := &GlobalOption{
		CheckDnsOptionRaw: CheckDnsOptionRaw{Raw: []string{"1.1.1.1:53"}},
		CheckInterval:     15 * time.Second,
	}
	d := NewDialer(&mockNetDialer{}, option, &Property{Property: D.Property{Name: "mock"}}, true)
	// Mark all 4 network types supported so Update() takes the regular path.
	supportedField := reflect.ValueOf(d).Elem().FieldByName("supported")
	if supportedField.IsValid() {
		ptr := unsafe.Pointer(supportedField.UnsafeAddr())
		*(*[4]bool)(ptr) = [4]bool{true, true, true, true}
	}
	return d
}

var testNetType = &common.NetworkType{
	L4Proto:   consts.L4ProtoStr_TCP,
	IpVersion: consts.IpVersionStr_4,
}

// TestDialer_ResetLatency_AcrossGroups verifies that ResetLatency clears both
// the per-group Latencies10 ring buffer and the per-group MovingAverage EMA,
// without disturbing the registered-groups map or any unrelated group.
func TestDialer_ResetLatency_AcrossGroups(t *testing.T) {
	d := newTestDialer(t)
	// Use named struct values with distinct `id` fields: zero-value composite
	// literals (or zero-value local vars) get aliased to the same stack slot
	// by the Go compiler, which would merge g1 and g2 in the interface-keyed
	// map. See the mockDialerGroup doc comment for details.
	g1 := &mockDialerGroup{id: 1}
	g2 := &mockDialerGroup{id: 2}
	if g1 == g2 {
		t.Fatal("test setup: g1 and g2 must be distinct pointers")
	}
	d.RegisterDialerGroup(g1)
	d.RegisterDialerGroup(g2)

	// Seed both groups with a few samples so we have something to clear.
	for i := 0; i < 3; i++ {
		d.Update(true, 100*time.Millisecond, testNetType, nil)
	}

	if _, ok := d.Latencies10[g1].LastLatency(); !ok {
		t.Fatal("Latencies10[g1] should have a sample before reset")
	}
	if d.MovingAverage[g1] == 0 {
		t.Fatal("MovingAverage[g1] should be non-zero before reset")
	}
	if len(d.registeredDialerGroups) != 2 {
		t.Fatalf("expected 2 registered groups, got %d", len(d.registeredDialerGroups))
	}

	d.ResetLatency()

	if _, ok := d.Latencies10[g1].LastLatency(); ok {
		t.Fatal("Latencies10[g1] should be empty after reset")
	}
	if _, ok := d.Latencies10[g2].LastLatency(); ok {
		t.Fatal("Latencies10[g2] should be empty after reset")
	}
	if d.MovingAverage[g1] != 0 {
		t.Fatalf("MovingAverage[g1] should be 0 after reset, got %v", d.MovingAverage[g1])
	}
	if d.MovingAverage[g2] != 0 {
		t.Fatalf("MovingAverage[g2] should be 0 after reset, got %v", d.MovingAverage[g2])
	}
	if len(d.registeredDialerGroups) != 2 {
		t.Fatalf("ResetLatency must not unregister groups; got %d", len(d.registeredDialerGroups))
	}
}

// TestDialer_ResetLatency_NoGroups makes sure the reset is a no-op (no panic)
// when no DialerGroup has been registered yet.
func TestDialer_ResetLatency_NoGroups(t *testing.T) {
	d := newTestDialer(t)
	// Should not panic on an empty registeredDialerGroups map.
	d.ResetLatency()
}

// TestDialer_RunInitialCheck_UsesWarmLatency verifies that the initial
// connectivity check re-checks the winning network type a second time and
// seeds the moving average with the WARM (second) sample rather than the cold
// first sample. This matters for TCP+mux protocols (e.g. anytls): the first
// check includes the TCP+TLS handshake, while the second reuses the dialer's
// session pool and reflects steady-state latency.
func TestDialer_RunInitialCheck_UsesWarmLatency(t *testing.T) {
	d := newTestDialer(t)
	g := &mockDialerGroup{id: 1}
	d.RegisterDialerGroup(g)
	// Skip the Connect() path: runInitialCheck dials only when !Alive().
	d.alive.Store(true)

	var calls atomic.Int32
	opt := &CheckOption{
		networkType: testNetType,
		CheckFunc: func() (bool, error) {
			if calls.Add(1) == 1 {
				// Simulate a cold TCP+TLS handshake on the first check.
				time.Sleep(300 * time.Millisecond)
			}
			return true, nil
		},
	}

	if returned := d.runInitialCheck([]*CheckOption{opt}); returned != opt {
		t.Fatalf("runInitialCheck should return the winning opt, got %v", returned)
	}
	if got := calls.Load(); got != 2 {
		t.Fatalf("expected CheckFunc to be called twice (cold + warm), got %d", got)
	}
	// The seed must reflect the warm (~0) sample, not the 300ms cold sample.
	if ma := d.MovingAverage[g]; ma >= 100*time.Millisecond {
		t.Fatalf("moving average should be seeded with the warm sample, got %v", ma)
	}
}
