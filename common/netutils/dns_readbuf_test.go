package netutils

import (
	"context"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/daeuniverse/outbound/netproxy"
	dnsmessage "github.com/miekg/dns"
)

// bigAnswerDialer hands out connections that answer every query with a fixed
// oversized DNS response, so the resolver's read buffer can be driven without
// a real upstream. The environment does not deliver large loopback UDP
// datagrams reliably, so an in-process conn is the only way to attribute a
// result to the buffer size.
type bigAnswerDialer struct {
	resp []byte
}

func (d *bigAnswerDialer) Alive() bool       { return true }
func (d *bigAnswerDialer) Connect() error    { return nil }
func (d *bigAnswerDialer) Disconnect() error { return nil }

func (d *bigAnswerDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	return &bigAnswerConn{resp: d.resp}, nil
}

func (d *bigAnswerDialer) ListenPacket(ctx context.Context, address string) (net.PacketConn, error) {
	return nil, netproxy.UnsupportedTunnelTypeError
}

type bigAnswerConn struct {
	resp []byte
}

func (c *bigAnswerConn) Read(p []byte) (int, error) {
	// A datagram reader truncates when the buffer is too small, exactly like
	// a UDP socket: the caller then sees a short, unparsable message.
	n := copy(p, c.resp)
	return n, nil
}
func (c *bigAnswerConn) Write(p []byte) (int, error)      { return len(p), nil }
func (c *bigAnswerConn) Close() error                     { return nil }
func (c *bigAnswerConn) LocalAddr() net.Addr              { return &net.UDPAddr{} }
func (c *bigAnswerConn) RemoteAddr() net.Addr             { return &net.UDPAddr{} }
func (c *bigAnswerConn) SetDeadline(time.Time) error      { return nil }
func (c *bigAnswerConn) SetReadDeadline(time.Time) error  { return nil }
func (c *bigAnswerConn) SetWriteDeadline(time.Time) error { return nil }

// bigDNSResponse builds a response for example.com/A whose packed size exceeds
// 2048 bytes (the old EthernetMtu pool bucket) by filling the answer section.
func bigDNSResponse(t *testing.T) []byte {
	t.Helper()
	msg := new(dnsmessage.Msg)
	msg.SetReply(new(dnsmessage.Msg))
	q := new(dnsmessage.Msg)
	q.SetQuestion("example.com.", dnsmessage.TypeA)
	msg.SetReply(q)
	for i := 0; i < 200; i++ {
		msg.Answer = append(msg.Answer, &dnsmessage.A{
			Hdr: dnsmessage.RR_Header{
				Name:   "example.com.",
				Rrtype: dnsmessage.TypeA,
				Class:  dnsmessage.ClassINET,
				Ttl:    300,
			},
			A: net.IPv4(192, 0, 2, byte(i%255)),
		})
	}
	packed, err := msg.Pack()
	if err != nil {
		t.Fatalf("pack response: %v", err)
	}
	if len(packed) <= 2048 {
		t.Fatalf("test response is only %d bytes; it must exceed the old 2048 buffer", len(packed))
	}
	return packed
}

// TestResolveUDPReadBufferHoldsFullDNSMessage pins the read buffer of the
// internal resolver: sized at the old EthernetMtu pool bucket (2048), an
// oversized answer was read short and reported as a decode failure instead of
// being delivered.
func TestResolveUDPReadBufferHoldsFullDNSMessage(t *testing.T) {
	dialer := &bigAnswerDialer{resp: bigDNSResponse(t)}
	answers, err := resolve(dialer, netip.MustParseAddrPort("127.0.0.1:53"), "example.com", dnsmessage.TypeA, "udp")
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if len(answers) != 200 {
		t.Fatalf("got %d answers, want 200: the read buffer truncated the response", len(answers))
	}
}
