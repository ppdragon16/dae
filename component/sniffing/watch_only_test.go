package sniffing

import (
	"bytes"
	"net"
	"testing"
	"time"
)

// scriptedConn serves a canned stream from Read; the other net.Conn methods
// are no-ops suitable for a loopback test.
type scriptedConn struct {
	data []byte
}

func (c *scriptedConn) Read(p []byte) (int, error) {
	if len(c.data) == 0 {
		return 0, net.ErrClosed
	}
	n := copy(p, c.data)
	c.data = c.data[n:]
	return n, nil
}
func (c *scriptedConn) Write(p []byte) (int, error)      { return len(p), nil }
func (c *scriptedConn) Close() error                     { return nil }
func (c *scriptedConn) LocalAddr() net.Addr              { return nil }
func (c *scriptedConn) RemoteAddr() net.Addr             { return nil }
func (c *scriptedConn) SetDeadline(time.Time) error      { return nil }
func (c *scriptedConn) SetReadDeadline(time.Time) error  { return nil }
func (c *scriptedConn) SetWriteDeadline(time.Time) error { return nil }

// relayThrough plays the stream through the WatchOnlyConnSniffer's Read --
// the same path the relay uses -- and returns what the relay would forward.
func relayThrough(t *testing.T, w *WatchOnlyConnSniffer, stream []byte, chunk int) []byte {
	t.Helper()
	p := make([]byte, chunk)
	var out []byte
	done := 0
	for done < len(stream) {
		n, err := w.Read(p)
		out = append(out, p[:n]...)
		done += n
		if err != nil {
			t.Fatalf("read: %v", err)
		}
		if n == 0 {
			t.Fatal("read made no progress")
		}
	}
	return out
}

// TestWatchOnlyLearnsAndRelaysIntact is the core of the feature: the relay
// consumes every chunk, the learned domain reaches onDomain exactly once, and
// the relayed bytes are the stream itself.
func TestWatchOnlyLearnsAndRelaysIntact(t *testing.T) {
	var got []byte
	fired := make(chan string, 1)
	w := NewWatchOnlyConnSniffer(&scriptedConn{data: tlsStreamGoogle}, 300*time.Millisecond, func(domain string) {
		fired <- domain
		close(fired)
	})

	got = relayThrough(t, w, tlsStreamGoogle, 200)

	if !bytes.Equal(got, tlsStreamGoogle) {
		t.Fatalf("relayed %d bytes, want the full stream intact", len(got))
	}
	select {
	case domain := <-fired:
		if domain != "www.google.com" {
			t.Fatalf("domain = %q, want www.google.com", domain)
		}
	default:
		t.Fatal("onDomain was never called with the learned domain")
	}
}

// TestWatchOnlyReportsEmptyOnJunk pins the terminal-verdict shape: bytes that
// are not a sniffer protocol decide immediately, with an empty domain.
func TestWatchOnlyReportsEmptyOnJunk(t *testing.T) {
	stream := []byte{0x00, 0x01, 0x02, 0x03, 0x04, 0x05}
	fired := make(chan string, 1)
	w := NewWatchOnlyConnSniffer(&scriptedConn{data: stream}, 300*time.Millisecond, func(domain string) {
		fired <- domain
	})

	relayThrough(t, w, stream, 6)

	select {
	case domain := <-fired:
		if domain != "" {
			t.Fatalf("domain = %q, want empty", domain)
		}
	case <-time.After(time.Second):
		t.Fatal("onDomain was never called")
	}
}

// TestWatchOnlyCloseBeforeDataFiresOnce pins that a connection closed before
// any data still reports (empty domain), exactly once.
func TestWatchOnlyCloseBeforeDataFiresOnce(t *testing.T) {
	w := NewWatchOnlyConnSniffer(&scriptedConn{data: nil}, 300*time.Millisecond, nil)
	count := 0
	w.onDomain = func(domain string) {
		count++
		if domain != "" {
			t.Fatalf("domain = %q", domain)
		}
	}

	if err := w.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("second close: %v", err)
	}
	if count != 1 {
		t.Fatalf("onDomain called %d times, want 1", count)
	}
}
