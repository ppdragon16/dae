package dialer

import (
	"testing"
	"time"
)

// TestRecoveryEdgeResetsLatencyHistory pins the recovery semantics: the
// failure that flips a dialer not-alive files timeout-penalty samples into
// every group's moving average, and an EMA over them decays far slower than
// the node recovers -- so min_moving_avg kept routing away from a node that
// was back (observed: [NOT ALIVE --> ALIVE] with mov_avg 2.545s, traffic only
// returned after the next update-sub, whose ResetLatency did instantly what
// the recovery edge now does on its own).
//
// A penalty-carrying failure must therefore behave like the update-sub path:
// the first Update(true) after a not-alive period clears the history, so the
// moving average restarts from the fresh sample instead of the poisoned one.
func TestRecoveryEdgeResetsLatencyHistory(t *testing.T) {
	g := &mockDialerGroup{id: 1}
	d := NewDialer(&mockNetDialer{}, &GlobalOption{CheckInterval: time.Hour}, &Property{}, false)
	d.RegisterDialerGroup(g)

	// Warm history, then a failure: Update(false) files the group's timeout
	// penalty as the sample. The mock's penalty is 0, so use a large explicit
	// latency on the failure to stand in for the penalty the real group files.
	d.Update(true, 100*time.Millisecond, testNetType, nil)
	d.Update(false, 5*time.Second, testNetType, nil)
	if !d.alive.Load() == false {
		t.Fatal("test setup: dialer should be not alive after a failed check")
	}
	if d.MovingAverage[g] != 1570*time.Millisecond {
		t.Fatalf("test setup: mov_avg = %v, want 1.57s (EMA of 100ms then the 5s failure)", d.MovingAverage[g])
	}

	// Recovery edge: first success after the not-alive period.
	d.Update(true, 90*time.Millisecond, testNetType, nil)

	// Without the reset the EMA would still carry the penalty: the next
	// sample alone would leave ((1-alpha)*1.57s + alpha*90ms ≈ 1.13s); with it
	// the history starts from the fresh sample alone.
	if got := d.MovingAverage[g]; got != 90*time.Millisecond {
		t.Fatalf("after the recovery edge mov_avg = %v, want a clean 90ms restart (no penalty residue)", got)
	}
	if _, ok := d.Latencies10[g].LastLatency(); !ok {
		t.Fatal("after the recovery edge Latencies10 should hold the fresh sample")
	}
}
