package dialer

import (
	"sync/atomic"
	"testing"
	"time"

	D "github.com/daeuniverse/outbound/dialer"
	"github.com/daeuniverse/outbound/netproxy"
)

// countingUnderlying counts Disconnect calls: the shared-pool teardown that
// must fire only when the LAST wrapper closes.
type countingUnderlying struct {
	mockNetDialer
	disconnects int32
}

func (u *countingUnderlying) Disconnect() error {
	atomic.AddInt32(&u.disconnects, 1)
	return nil
}

func newRefTestDialer(u netproxy.Dialer) *Dialer {
	return NewDialer(u, &GlobalOption{CheckInterval: time.Second}, &Property{Property: D.Property{Name: "n"}}, false)
}

// Closing one of several wrappers sharing an underlying dialer must NOT
// disconnect it: other groups still reference the node through their own
// wrappers. This is the update-sub clone scenario (group-level option
// override → Clone → same underlying, distinct wrappers).
func TestSharedUnderlyingCloseKeepsPool(t *testing.T) {
	u := &countingUnderlying{}
	w1 := newRefTestDialer(u)
	w2 := w1.Clone()

	if err := w1.Close(); err != nil {
		t.Fatal(err)
	}
	if n := atomic.LoadInt32(&u.disconnects); n != 0 {
		t.Fatalf("underlying disconnected while w2 still references it (%d times)", n)
	}

	// Last wrapper out disconnects the underlying exactly once.
	if err := w2.Close(); err != nil {
		t.Fatal(err)
	}
	if n := atomic.LoadInt32(&u.disconnects); n != 1 {
		t.Fatalf("underlying disconnected %d times after last Close, want 1", n)
	}
}

// A plain (uncloned) dialer keeps the legacy behavior: its Close disconnects.
func TestSoloUnderlyingCloseDisconnects(t *testing.T) {
	u := &countingUnderlying{}
	w := newRefTestDialer(u)
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	if n := atomic.LoadInt32(&u.disconnects); n != 1 {
		t.Fatalf("underlying disconnected %d times, want 1", n)
	}
}

// The same underlying recovered across update-sub generations (recycled old
// instance) must keep its refcount coherent: a fresh discarded wrapper's
// Close must not disconnect it.
func TestRecycledAcrossGenerations(t *testing.T) {
	u := &countingUnderlying{}
	// Generation 1: node built, used by a group.
	w1 := newRefTestDialer(u)
	// Generation 2: update-sub builds a fresh wrapper over the SAME
	// underlying — only possible when the wrapper is recycled, so model the
	// kept instance plus the discarded fresh one.
	wKept := w1          // recycled old instance stays in the group
	wFresh := w1.Clone() // fresh build discarded by ReplaceDialers

	if err := wFresh.Close(); err != nil {
		t.Fatal(err)
	}
	if atomic.LoadInt32(&u.disconnects) != 0 {
		t.Fatal("discarded fresh wrapper disconnected the recycled underlying")
	}
	if err := wKept.Close(); err != nil {
		t.Fatal(err)
	}
	if n := atomic.LoadInt32(&u.disconnects); n != 1 {
		t.Fatalf("underlying disconnected %d times after last Close, want 1", n)
	}
}
