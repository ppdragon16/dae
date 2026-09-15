package control

import (
	"errors"
	"io"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// errConn returns err from every Read, passing everything else through.
type errConn struct {
	net.Conn
	readErr error
}

func (c *errConn) Read(p []byte) (int, error) { return 0, c.readErr }

// TestRelayDirectionSwallowsClosedPipe pins that io.ErrClosedPipe — the
// canonical smux stream/session-closed signal — is treated as normal
// termination like EOF/net.ErrClosed, instead of surfacing in the
// "handleConn: RelayTCP" error log.
func TestRelayDirectionSwallowsClosedPipe(t *testing.T) {
	l1, l2 := net.Pipe()
	defer l1.Close()
	defer l2.Close()

	// readIdle is a required, pre-armed shared bound (see relayDirection).
	var readIdle atomic.Int64
	readIdle.Store(int64(DefaultTCPIdleTimeout))
	src := func(readErr error) *errConn { return &errConn{Conn: l2, readErr: readErr} }

	if err := relayDirection(l1, src(io.ErrClosedPipe), &readIdle); err != nil {
		t.Fatalf("io.ErrClosedPipe should be swallowed, got %v", err)
	}
	if err := relayDirection(l1, src(io.EOF), &readIdle); err != nil {
		t.Fatalf("io.EOF should be swallowed, got %v", err)
	}
	if err := relayDirection(l1, src(net.ErrClosed), &readIdle); err != nil {
		t.Fatalf("net.ErrClosed should be swallowed, got %v", err)
	}
	// Real errors must keep surfacing.
	boom := errors.New("boom")
	if err := relayDirection(l1, src(boom), &readIdle); !errors.Is(err, boom) {
		t.Fatalf("unexpected error should surface, got %v", err)
	}
}

// deadlineConn records every SetReadDeadline and returns (n, nil) reads from
// pending until drained, then hangs until its tracked read deadline fires
// (timeout error) or blocking is closed (clean EOF).
type deadlineConn struct {
	deadline     []time.Time
	readDeadline time.Time
	pending      [][]byte
	blocking     chan struct{}
	hung         chan struct{}
	hungOnce     sync.Once
}

func (c *deadlineConn) SetReadDeadline(t time.Time) error {
	c.deadline = append(c.deadline, t)
	c.readDeadline = t
	return nil
}

func (c *deadlineConn) Read(p []byte) (int, error) {
	if len(c.pending) > 0 {
		n := copy(p, c.pending[0])
		c.pending = c.pending[1:]
		return n, nil
	}
	c.hungOnce.Do(func() { close(c.hung) })
	if !c.readDeadline.IsZero() {
		timer := time.NewTimer(time.Until(c.readDeadline))
		defer timer.Stop()
		select {
		case <-c.blocking:
		case <-timer.C:
			return 0, os.ErrDeadlineExceeded
		}
	} else {
		<-c.blocking
	}
	return 0, io.EOF
}

func (c *deadlineConn) Write(p []byte) (int, error) { return len(p), nil }

func (c *deadlineConn) SetDeadline(t time.Time) error    { return c.SetReadDeadline(t) }
func (c *deadlineConn) SetWriteDeadline(time.Time) error { return nil }
func (c *deadlineConn) Close() error                     { return nil }
func (c *deadlineConn) LocalAddr() net.Addr              { return nil }
func (c *deadlineConn) RemoteAddr() net.Addr             { return nil }

// writeRecorder swallows writes, recording their payload.
type writeRecorder struct {
	written []byte
}

func (w *writeRecorder) Read(p []byte) (int, error) { return 0, io.EOF }
func (w *writeRecorder) Write(p []byte) (int, error) {
	w.written = append(w.written, p...)
	return len(p), nil
}
func (w *writeRecorder) Close() error                     { return nil }
func (w *writeRecorder) SetDeadline(time.Time) error      { return nil }
func (w *writeRecorder) SetReadDeadline(time.Time) error  { return nil }
func (w *writeRecorder) SetWriteDeadline(time.Time) error { return nil }
func (w *writeRecorder) LocalAddr() net.Addr              { return nil }
func (w *writeRecorder) RemoteAddr() net.Addr             { return nil }

// TestRelayDirectionClampsReArmAfterHalfClose pins the half-close re-arm
// clamp: once the l2r direction has ended cleanly, relay data still in
// flight must not resurrect the full idle timeout — the read bound stays at
// the half-close scale so a peer that goes silent without FIN cannot park
// the relay for an hour.
func TestRelayDirectionClampsReArmAfterHalfClose(t *testing.T) {
	for _, tc := range []struct {
		name       string
		halfClosed bool
		want       time.Duration
	}{
		{"live stream keeps idle timeout", false, DefaultTCPIdleTimeout},
		{"half-closed stream is clamped", true, DefaultHalfCloseIdleTimeout},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dst := &writeRecorder{}
			src := &deadlineConn{
				pending:  [][]byte{[]byte("chunk")},
				blocking: make(chan struct{}),
				hung:     make(chan struct{}),
			}
			var readIdle atomic.Int64
			readIdle.Store(int64(DefaultTCPIdleTimeout))
			if tc.halfClosed {
				readIdle.Store(int64(DefaultHalfCloseIdleTimeout))
			}

			done := make(chan error, 1)
			go func() { done <- relayDirection(dst, src, &readIdle) }()

			// Wait until the relay has consumed the in-flight chunk,
			// re-armed, and hung on its next read.
			select {
			case <-src.hung:
			case <-time.After(5 * time.Second):
				t.Fatal("relay never hung on its next read")
			}
			if string(dst.written) != "chunk" {
				t.Fatalf("expected in-flight chunk to be relayed, got %q", dst.written)
			}

			if len(src.deadline) < 2 {
				t.Fatalf("expected initial arm plus at least one re-arm, got %d", len(src.deadline))
			}
			rearm := src.deadline[len(src.deadline)-1]
			if rearm.After(time.Now().Add(tc.want).Add(2 * time.Second)) {
				t.Fatalf("re-arm %v exceeds %v bound", rearm, tc.want)
			}

			if tc.halfClosed {
				// The clamped deadline must actually break the hung read:
				// the relay exits on its own within the grace, not an hour.
				select {
				case <-done:
				case <-time.After(DefaultHalfCloseIdleTimeout + 5*time.Second):
					t.Fatal("half-closed relay was not bounded by the grace")
				}
			} else {
				close(src.blocking)
				<-done
			}
		})
	}
}
