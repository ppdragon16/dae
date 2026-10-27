package component

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

func newTestInterfaceManager() *InterfaceManager {
	closed, toClose := context.WithCancel(context.Background())
	return &InterfaceManager{
		callbacks:  make([]callbackSet, 0),
		closed:     closed,
		close:      toClose,
		upLinks:    make(map[string]bool),
		operStates: make(map[string]netlink.LinkOperState),
	}
}

// TestInterfaceManagerRebindsOnOperStateUpTransition verifies that the binding
// callback is retriggered when a known link flaps down and comes back up. The
// kernel removes the ingress qdisc and TC filters on link down, so without
// this re-bind the dataplane would silently lose traffic steering after a flap.
// (Port of upstream #1049.)
func TestInterfaceManagerRebindsOnOperStateUpTransition(t *testing.T) {
	mgr := newTestInterfaceManager()

	var total atomic.Int32
	calls := make(chan string, 8)
	go func() {
		for range calls {
			total.Add(1)
		}
	}()

	mgr.callbacks = append(mgr.callbacks, callbackSet{
		pattern: "*",
		newCallback: func(link netlink.Link) {
			calls <- link.Attrs().Name
		},
	})

	ch := make(chan netlink.LinkUpdate)
	done := make(chan struct{})
	go mgr.monitor(ch, done, false)
	defer func() { _ = mgr.Close() }()

	const ifName = "eth0"
	// The monitor debounces callbacks; wait for the margin to elapse so any
	// pending callback has been dispatched before we assert.
	settle := func() { time.Sleep(300 * time.Millisecond) }
	send := func(state netlink.LinkOperState) {
		ch <- netlink.LinkUpdate{
			Header: unix.NlMsghdr{Type: unix.RTM_NEWLINK},
			Link:   &netlink.Dummy{LinkAttrs: netlink.LinkAttrs{Name: ifName, OperState: state}},
		}
	}

	// 1. First appearance (OperUp) must bind.
	send(netlink.OperUp)
	settle()
	if v := total.Load(); v != 1 {
		t.Fatalf("after first appearance: got %d bind callback(s), want 1", v)
	}

	// 2. A repeated OperUp (no state change) must NOT re-bind.
	send(netlink.OperUp)
	settle()
	if v := total.Load(); v != 1 {
		t.Fatalf("after repeated OperUp: got %d bind callback(s), want 1 (no extra rebind)", v)
	}

	// 3. Going down (OperDown) must NOT re-bind.
	send(netlink.OperDown)
	settle()
	if v := total.Load(); v != 1 {
		t.Fatalf("after OperDown: got %d bind callback(s), want 1 (no rebind on down)", v)
	}

	// 4. Coming back up (OperDown -> OperUp) MUST re-bind.
	send(netlink.OperUp)
	settle()
	if v := total.Load(); v != 2 {
		t.Fatalf("after flap back to OperUp: got %d bind callback(s), want 2 (rebind on up transition)", v)
	}
}
