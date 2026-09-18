package dialer

import (
	"net"
	"testing"
	"time"

	"github.com/daeuniverse/dae/common"
)

func newDeferredAbortDialer(interval time.Duration) *Dialer {
	d := NewDialer(&mockNetDialer{}, &GlobalOption{CheckInterval: interval}, &Property{}, false)
	d.alive.Store(true)
	return d
}

func registerPair(t *testing.T, d *Dialer) (lConn, rConn net.Conn) {
	t.Helper()
	lConn, rConn = net.Pipe()
	d.RegisterConn(lConn, rConn)
	return lConn, rConn
}

// A single failed check must NOT kill connections: the node flapped and
// recovered within one CheckInterval, so the deferred abort is cancelled.
func TestFlapRecoveryCancelsAbort(t *testing.T) {
	d := newDeferredAbortDialer(100 * time.Millisecond)
	lConn, rConn := registerPair(t, d)
	defer lConn.Close()
	defer rConn.Close()

	d.Update(false, 0, nil, errTest)
	d.Update(true, 10*time.Millisecond, nil, nil)
	time.Sleep(200 * time.Millisecond) // > CheckInterval

	if len(d.activeConns) != 1 {
		t.Fatalf("connections were aborted despite recovery")
	}
}

// Sustained not-alive across a full CheckInterval (two consecutive failed
// rounds) is a real death: connections are aborted.
func TestSustainedDeathAborts(t *testing.T) {
	d := newDeferredAbortDialer(80 * time.Millisecond)
	lConn, rConn := registerPair(t, d)
	defer lConn.Close()

	d.Update(false, 0, nil, errTest)
	// Simulate the next check round also failing (oldAlive already false,
	// so no new timer is armed).
	d.Update(false, 0, nil, errTest)

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) && len(d.activeConns) > 0 {
		time.Sleep(10 * time.Millisecond)
	}
	if len(d.activeConns) != 0 {
		t.Fatal("connections were not aborted after sustained not-alive")
	}
	_ = rConn
}

// Zero CheckInterval keeps the legacy immediate-abort behavior.
func TestZeroIntervalImmediateAbort(t *testing.T) {
	d := newDeferredAbortDialer(0)
	lConn, rConn := registerPair(t, d)
	defer lConn.Close()

	d.Update(false, 0, nil, errTest)
	if len(d.activeConns) != 0 {
		t.Fatal("legacy immediate abort with zero CheckInterval not preserved")
	}
	_ = rConn
}

var errTest = common.Errf("check failed: %v", "test")
