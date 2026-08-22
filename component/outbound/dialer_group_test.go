/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package outbound

import (
	"context"
	"net"
	"reflect"
	"testing"
	"time"
	"unsafe"

	"github.com/daeuniverse/dae/common"
	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/component/outbound/dialer"
	D "github.com/daeuniverse/outbound/dialer"
	"github.com/daeuniverse/outbound/netproxy"
	"github.com/daeuniverse/outbound/pkg/fastrand"
)

const (
	testTcpCheckUrl = "https://connectivitycheck.gstatic.com/generate_204"
	testUdpCheckDns = "1.1.1.1:53"
)

func TestMain(m *testing.M) {
	// Latency-based selectors dereference the global Metrics gauges in
	// logCheckLatency, so initialize them once for the whole package.
	// InitMetrics is idempotent, making repeated calls safe.
	common.InitMetrics()
	m.Run()
}

var TestNetworkType = &common.NetworkType{
	L4Proto:   consts.L4ProtoStr_TCP,
	IpVersion: consts.IpVersionStr_4,
}

type mockDialer struct {
	netproxy.Dialer
}

func (m *mockDialer) Alive() bool                                    { return true }
func (m *mockDialer) Name() string                                   { return "mock" }
func (m *mockDialer) Dial(network, address string) (net.Conn, error) { return nil, nil }
func (m *mockDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	return nil, nil
}
func (m *mockDialer) ListenPacket(ctx context.Context, address string) (net.PacketConn, error) {
	return nil, nil
}

func newDirectDialer(option *dialer.GlobalOption, needAliveState bool) *dialer.Dialer {
	d := dialer.NewDialer(&mockDialer{}, option, &dialer.Property{Property: D.Property{Name: "mock"}}, needAliveState)
	// Use unsafe to set unexported supported field
	supportedField := reflect.ValueOf(d).Elem().FieldByName("supported")
	if supportedField.IsValid() {
		ptr := unsafe.Pointer(supportedField.UnsafeAddr())
		*(*[4]bool)(ptr) = [4]bool{true, true, true, true}
	}
	return d
}

func TestDialerGroup_Select_Fixed(t *testing.T) {
	option := &dialer.GlobalOption{
		CheckDnsOptionRaw: dialer.CheckDnsOptionRaw{Raw: []string{testUdpCheckDns}},
		CheckInterval:     15 * time.Second,
		CheckTolerance:    0,
		CheckDnsTcp:       false,
	}
	dialers := []*dialer.Dialer{
		newDirectDialer(option, true),
		newDirectDialer(option, false),
	}
	fixedIndex := 1
	g := NewDialerGroup(option, "test-group", dialers, make([]*dialer.Annotation, len(dialers)),
		dialer.DialerSelectionPolicy{
			Policy:     consts.DialerSelectionPolicy_Fixed,
			FixedIndex: fixedIndex,
		}, func(alive bool, networkType *common.NetworkType) {})
	for i := 0; i < 10; i++ {
		d, err := g.Select(TestNetworkType)
		if err != nil {
			t.Fatal("step 1:", err)
		}
		if d != dialers[fixedIndex] {
			t.Fail()
		}
	}

	fixedIndex = 0
	g.selectionPolicy.FixedIndex = fixedIndex
	dialers[fixedIndex].Update(true, 0, TestNetworkType, nil)
	for i := 0; i < 10; i++ {
		d, err := g.Select(TestNetworkType)
		if err != nil {
			t.Fatal("step 2:", err)
		}
		if d != dialers[fixedIndex] {
			t.Fail()
		}
	}
}

func TestDialerGroup_Select_MinLastLatency(t *testing.T) {
	option := &dialer.GlobalOption{
		CheckDnsOptionRaw: dialer.CheckDnsOptionRaw{Raw: []string{testUdpCheckDns}},
		CheckInterval:     15 * time.Second,
	}
	dialers := make([]*dialer.Dialer, 10)
	for i := range dialers {
		dialers[i] = newDirectDialer(option, false)
	}
	annos := make([]*dialer.Annotation, 10)
	for i := range annos {
		annos[i] = &dialer.Annotation{}
	}
	g := NewDialerGroup(option, "test-group", dialers, annos,
		dialer.DialerSelectionPolicy{
			Policy: consts.DialerSelectionPolicy_MinLastLatency,
		}, func(alive bool, networkType *common.NetworkType) {})

	// Test 1000 times.
	for i := 0; i < 1000; i++ {
		var minLatency time.Duration
		jMinLatency := -1
		for j, d := range dialers {
			// Simulate a latency test.
			var (
				latency time.Duration
				alive   bool
			)
			// 20% chance for timeout.
			if fastrand.Intn(5) == 0 {
				// Simulate a timeout test.
				latency = 1000 * time.Millisecond
				alive = false
			} else {
				// Simulate a normal test.
				latency = time.Duration(fastrand.Int63n(int64(1000 * time.Millisecond)))
				alive = true
			}
			d.Update(alive, latency, TestNetworkType, nil)
			if alive && (jMinLatency == -1 || latency < minLatency) {
				jMinLatency = j
				minLatency = latency
			}
		}
		if jMinLatency == -1 {
			continue
		}
		d, err := g.Select(TestNetworkType)
		if err != nil {
			t.Fatal(err)
		}
		if d != dialers[jMinLatency] {
			// Get index of d.
			indexD := -1
			for j := range dialers {
				if d == dialers[j] {
					indexD = j
					break
				}
			}
			t.Errorf("dialers[%v] expected, but dialers[%v] selected", jMinLatency, indexD)
		}
	}
}

func TestDialerGroup_Select_Random(t *testing.T) {
	option := &dialer.GlobalOption{
		CheckDnsOptionRaw: dialer.CheckDnsOptionRaw{Raw: []string{testUdpCheckDns}},
		CheckInterval:     15 * time.Second,
	}
	dialers := make([]*dialer.Dialer, 5)
	for i := range dialers {
		dialers[i] = newDirectDialer(option, false)
	}
	annos := make([]*dialer.Annotation, 5)
	for i := range annos {
		annos[i] = &dialer.Annotation{}
	}
	g := NewDialerGroup(option, "test-group", dialers, annos,
		dialer.DialerSelectionPolicy{
			Policy: consts.DialerSelectionPolicy_Random,
		}, func(alive bool, networkType *common.NetworkType) {})
	count := make([]int, len(dialers))
	for i := 0; i < 100; i++ {
		d, err := g.Select(TestNetworkType)
		if err != nil {
			t.Fatal(err)
		}
		for j, dd := range dialers {
			if d == dd {
				count[j]++
				break
			}
		}
	}
	for i, c := range count {
		if c == 0 {
			t.Fail()
		}
		t.Logf("count[%v]: %v", i, c)
	}
}

// movingAverageOf pulls the per-group MovingAverage out of a *dialer.Dialer
// for assertion. It mirrors the unsafe trick in newDirectDialer for reaching
// unexported fields from the test package. The group is taken as a
// dialer.DialerGroup interface so the map lookup uses the same key type that
// the dialer package stores internally.
func movingAverageOf(d *dialer.Dialer, g dialer.DialerGroup) time.Duration {
	mv := reflect.ValueOf(d).Elem().FieldByName("MovingAverage")
	ma := mv.MapIndex(reflect.ValueOf(g))
	if !ma.IsValid() {
		return 0
	}
	// map value is time.Duration (int64); no Elem() dereference needed.
	return time.Duration(ma.Int())
}

// latenciesCountOf returns the number of samples currently held in Latencies10
// for a given group, again via reflection for test-only access.
func latenciesCountOf(d *dialer.Dialer, g dialer.DialerGroup) int {
	lv := reflect.ValueOf(d).Elem().FieldByName("Latencies10")
	la := lv.MapIndex(reflect.ValueOf(g))
	if !la.IsValid() {
		return 0
	}
	// la is *LatenciesN; one Elem() dereferences the pointer.
	ln := la.Elem().FieldByName("count")
	return int(ln.Int())
}

// TestDialerGroup_ReplaceDialers_ResetsLatencyForRecoveredDialer exercises the
// update-sub recycle path: when the recycled dialer is currently !Alive(),
// Latencies10/MovingAverage must be reset so TimeoutPenalty samples from the
// previous down period do not survive into the recovered metrics. A dialer
// that is still alive keeps its history (no reset).
func TestDialerGroup_ReplaceDialers_ResetsLatencyForRecoveredDialer(t *testing.T) {
	// logCheckLatency (called by latency-based selectors) dereferences the
	// global Metrics gauge. InitMetrics is idempotent so calling it here is
	// safe even if the test runs in a process that also initialised metrics
	// elsewhere.
	common.InitMetrics()

	option := &dialer.GlobalOption{
		CheckDnsOptionRaw: dialer.CheckDnsOptionRaw{Raw: []string{testUdpCheckDns}},
		CheckInterval:     15 * time.Second,
	}
	d := newDirectDialer(option, true)
	anno := &dialer.Annotation{}
	// Use a latency-based policy so the test exercises the same selector
	// NotifyStatusChange path as production.
	g := NewDialerGroup(option, "test-group", []*dialer.Dialer{d},
		[]*dialer.Annotation{anno},
		dialer.DialerSelectionPolicy{Policy: consts.DialerSelectionPolicy_MinLastLatency},
		func(alive bool, networkType *common.NetworkType) {},
	)

	// Seed the dialer with one good sample, then a failed one so it ends up
	// !Alive and Latencies10 has at least one entry. The exact values are
	// irrelevant — we only assert the *delta* before/after recycle.
	d.Update(true, 100*time.Millisecond, TestNetworkType, nil)
	d.Update(false, 0, TestNetworkType, nil)
	if d.Alive() {
		t.Fatal("setup: expected dialer to be not alive after Update(false)")
	}
	// The dialer's Latencies10/MovingAverage are keyed by the dialer.DialerGroup
	// interface type, so we need to look them up via the same interface value
	// (not the concrete *DialerGroup pointer, which is a different key type).
	var dg dialer.DialerGroup = g
	if latenciesCountOf(d, dg) == 0 {
		t.Fatal("setup: expected Latencies10 to have at least one sample")
	}
	beforeMA := movingAverageOf(d, dg)

	// Update-sub with the same Property: dialer should be recycled.
	g.ReplaceDialers([]*dialer.Dialer{d}, []*dialer.Annotation{anno})
	if g.Dialers[0] != d {
		t.Fatal("expected dialer pointer to be recycled (Property match)")
	}
	if latenciesCountOf(d, dg) != 0 {
		t.Fatalf("recycled !alive dialer: Latencies10 should be empty, got %d samples",
			latenciesCountOf(d, dg))
	}
	if got := movingAverageOf(d, dg); got != 0 {
		t.Fatalf("recycled !alive dialer: MovingAverage should be 0, got %v (was %v before)",
			got, beforeMA)
	}

	// Now the same Property match but the dialer is alive — history must stick.
	d.Update(true, 80*time.Millisecond, TestNetworkType, nil)
	if !d.Alive() {
		t.Fatal("setup: expected dialer to be alive after Update(true)")
	}
	if latenciesCountOf(d, dg) == 0 {
		t.Fatal("setup: expected Latencies10 to be non-empty for alive dialer")
	}
	aliveMA := movingAverageOf(d, dg)
	g.ReplaceDialers([]*dialer.Dialer{d}, []*dialer.Annotation{anno})
	if g.Dialers[0] != d {
		t.Fatal("expected dialer pointer to be recycled (alive case)")
	}
	if latenciesCountOf(d, dg) == 0 {
		t.Fatal("recycled alive dialer: Latencies10 should be preserved, but is empty")
	}
	if got := movingAverageOf(d, dg); got != aliveMA {
		t.Fatalf("recycled alive dialer: MovingAverage changed from %v to %v", aliveMA, got)
	}
}

func TestDialerGroup_SetAlive(t *testing.T) {
	option := &dialer.GlobalOption{
		CheckDnsOptionRaw: dialer.CheckDnsOptionRaw{Raw: []string{testUdpCheckDns}},
		CheckInterval:     15 * time.Second,
	}
	dialers := make([]*dialer.Dialer, 5)
	for i := range dialers {
		dialers[i] = newDirectDialer(option, true)
	}
	annos := make([]*dialer.Annotation, 5)
	for i := range annos {
		annos[i] = &dialer.Annotation{}
	}
	g := NewDialerGroup(option, "test-group", dialers, annos,
		dialer.DialerSelectionPolicy{
			Policy: consts.DialerSelectionPolicy_Random,
		}, func(alive bool, networkType *common.NetworkType) {})
	for _, d := range dialers {
		d.Update(true, 0, TestNetworkType, nil)
	}
	zeroTarget := 3
	dialers[zeroTarget].Update(false, 0, TestNetworkType, nil)
	count := make([]int, len(dialers))
	for i := 0; i < 100; i++ {
		d, err := g.Select(TestNetworkType)
		if err != nil {
			t.Fatal(err)
		}
		for j, dd := range dialers {
			if d == dd {
				count[j]++
				break
			}
		}
	}
	for i, c := range count {
		if c == 0 && i != zeroTarget {
			t.Fail()
		}
		t.Logf("count[%v]: %v", i, c)
	}
	if count[zeroTarget] != 0 {
		t.Fail()
	}
}
