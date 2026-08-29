package control

import (
	"errors"
	"io"
	"net"
	"testing"
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

	if err := relayDirection(l1, &errConn{Conn: l2, readErr: io.ErrClosedPipe}); err != nil {
		t.Fatalf("io.ErrClosedPipe should be swallowed, got %v", err)
	}
	if err := relayDirection(l1, &errConn{Conn: l2, readErr: io.EOF}); err != nil {
		t.Fatalf("io.EOF should be swallowed, got %v", err)
	}
	if err := relayDirection(l1, &errConn{Conn: l2, readErr: net.ErrClosed}); err != nil {
		t.Fatalf("net.ErrClosed should be swallowed, got %v", err)
	}
	// Real errors must keep surfacing.
	boom := errors.New("boom")
	if err := relayDirection(l1, &errConn{Conn: l2, readErr: boom}); !errors.Is(err, boom) {
		t.Fatalf("unexpected error should surface, got %v", err)
	}
}
