package sniffing

import (
	"testing"

	"github.com/daeuniverse/outbound/pool"
)

// TestSniffProgressSnapshot pins the reporting contract used by the timeout log:
// the byte count is the full accumulated size, the head is capped, and the head
// is a copy -- a live view would let later reads change what the log reports.
func TestSniffProgressSnapshot(t *testing.T) {
	s := &Sniffer{buf: pool.NewPooledBuffer()}
	defer s.Close()

	if n, head := s.SniffProgress(); n != 0 || head != nil {
		t.Fatalf("empty sniffer = (%d, %v), want (0, nil)", n, head)
	}

	payload := make([]byte, 32)
	for i := range payload {
		payload[i] = byte(i + 1)
	}
	if _, err := s.buf.Write(payload); err != nil {
		t.Fatalf("write: %v", err)
	}

	n, head := s.SniffProgress()
	if n != len(payload) {
		t.Fatalf("n = %d, want %d (the full accumulated size)", n, len(payload))
	}
	if len(head) != sniffHeadBytes {
		t.Fatalf("head length = %d, want the %d-byte cap", len(head), sniffHeadBytes)
	}
	if head[0] != 1 || head[sniffHeadBytes-1] != sniffHeadBytes {
		t.Fatalf("head = % x, want the leading bytes in order", head)
	}

	// The snapshot must not alias the live buffer: overwriting the buffered
	// bytes afterwards cannot change what this report says.
	s.buf.Bytes()[0] = 0xFF
	if head[0] != 1 {
		t.Fatal("head aliases the sniffer's buffer; a later read would rewrite the report")
	}
}

// TestSniffProgressNilReceiver pins the detached case: ConnSniffer nils its
// embedded sniffer once it drains, and the timeout path must still report
// rather than panic.
func TestSniffProgressNilReceiver(t *testing.T) {
	var s *Sniffer
	if n, head := s.SniffProgress(); n != 0 || head != nil {
		t.Fatalf("nil sniffer = (%d, %v), want (0, nil)", n, head)
	}
}
