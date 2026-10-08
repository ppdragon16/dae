package control

import (
	"net"
	"net/netip"
	"testing"
	"time"
)

var _ = netip.AddrPort{}

// newAnyfromOnLoopback builds an Anyfrom over a real loopback UDP socket (the
// pool's own Obtain needs the netns worker, which a unit test does not drive).
func newAnyfromOnLoopback(t *testing.T) (*Anyfrom, netipAddrPortPeer) {
	t.Helper()
	local, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("listen local: %v", err)
	}
	t.Cleanup(func() { _ = local.Close() })

	peer, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("listen peer: %v", err)
	}
	t.Cleanup(func() { _ = peer.Close() })

	return &Anyfrom{UDPConn: local}, netipAddrPortPeer{peer: peer}
}

type netipAddrPortPeer struct{ peer *net.UDPConn }

// readEmpty drains one datagram and requires it to be zero-length.
func (p netipAddrPortPeer) readEmpty(t *testing.T, within time.Duration) bool {
	t.Helper()
	_ = p.peer.SetReadDeadline(time.Now().Add(within))
	buf := make([]byte, 8)
	n, _, err := p.peer.ReadFromUDPAddrPort(buf)
	if err != nil {
		return false
	}
	if n != 0 {
		t.Fatalf("received a %d-byte datagram, want only zero-length ones", n)
	}
	return true
}

// TestBatchWriteToAddrPortSendsEmptyDatagram pins the zero-length datagram: the
// pool hands out an empty (non-nil) slice for it, and taking &data[0] to build
// the iovec panicked inside flushLocked -- on the batch timer or the packet
// goroutine, so an unrecovered panic took the process down. A client sending a
// burst of empty datagrams reached that path through WriteToAddrPort's batched
// branch.
func TestBatchWriteToAddrPortSendsEmptyDatagram(t *testing.T) {
	af, peer := newAnyfromOnLoopback(t)
	dst := peer.peer.LocalAddr().(*net.UDPAddr).AddrPort()

	n, err := af.BatchWriteToAddrPort(nil, dst)
	if err != nil {
		t.Fatalf("BatchWriteToAddrPort: %v", err)
	}
	if n != 0 {
		t.Fatalf("BatchWriteToAddrPort reported %d bytes for an empty datagram", n)
	}

	if !peer.readEmpty(t, 500*time.Millisecond) {
		t.Fatal("the empty datagram was never flushed to the peer")
	}
}

// TestWriteToAddrPortBurstOfEmptyDatagrams drives the burst path that enters
// batching after batchThreshold writes in one window: every datagram must
// arrive, none may be lost to a failed flush, and the process must survive.
func TestWriteToAddrPortBurstOfEmptyDatagrams(t *testing.T) {
	af, peer := newAnyfromOnLoopback(t)
	dst := peer.peer.LocalAddr().(*net.UDPAddr).AddrPort()

	const writes = 2 * sendBufSlots
	for range writes {
		if _, err := af.WriteToAddrPort(nil, dst); err != nil {
			t.Fatalf("WriteToAddrPort: %v", err)
		}
	}

	got := 0
	deadline := time.Now().Add(2 * time.Second)
	for got < writes && time.Now().Before(deadline) {
		if !peer.readEmpty(t, time.Until(deadline)) {
			break
		}
		got++
	}
	if got != writes {
		t.Fatalf("peer received %d empty datagrams, want %d", got, writes)
	}
}
