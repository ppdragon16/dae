package netutils

import (
	"context"
	"net"
	"net/netip"
	"testing"

	dnsmessage "github.com/miekg/dns"

	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/outbound/netproxy"
)

// testNetDialer is a netproxy.Dialer that dials through the system stack.
type testNetDialer struct{}

func (d *testNetDialer) Alive() bool    { return true }
func (d *testNetDialer) Connect() error { return nil }

func (d *testNetDialer) Disconnect() error { return nil }

func (d *testNetDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	var nd net.Dialer
	return nd.DialContext(ctx, network, address)
}

func (d *testNetDialer) ListenPacket(ctx context.Context, address string) (net.PacketConn, error) {
	return net.ListenPacket("udp", address)
}

var _ netproxy.Dialer = (*testNetDialer)(nil)

// startUDPDNSRcode starts a UDP DNS responder that answers every query with
// rcode and no answer records: what a failing or empty upstream looks like on
// the wire, without needing a real resolver.
func startUDPDNSRcode(t *testing.T, rcode int) netip.AddrPort {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen udp: %v", err)
	}
	t.Cleanup(func() { _ = pc.Close() })
	go func() {
		buf := make([]byte, consts.DnsMaxMessageSize)
		for {
			n, addr, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			var req dnsmessage.Msg
			if err := req.Unpack(buf[:n]); err != nil {
				continue
			}
			resp := new(dnsmessage.Msg)
			resp.SetReply(&req)
			resp.Rcode = rcode
			out, err := resp.Pack()
			if err != nil {
				continue
			}
			_, _ = pc.WriteTo(out, addr)
		}
	}()
	return netip.MustParseAddrPort(pc.LocalAddr().String())
}

func packedAnswer(t *testing.T, rcode int, withA bool) ([]byte, uint16) {
	t.Helper()
	m := new(dnsmessage.Msg)
	m.SetQuestion("example.com.", dnsmessage.TypeA)
	m.Response = true
	m.RecursionAvailable = true
	m.Rcode = rcode
	if withA {
		m.Answer = append(m.Answer, &dnsmessage.A{
			Hdr: dnsmessage.RR_Header{
				Name:   "example.com.",
				Rrtype: dnsmessage.TypeA,
				Class:  dnsmessage.ClassINET,
				Ttl:    60,
			},
			A: net.IPv4(93, 184, 216, 34).To4(),
		})
	}
	const id = 0x4242
	m.Id = id
	b, err := m.Pack()
	if err != nil {
		t.Fatalf("pack: %v", err)
	}
	return b, id
}

func startUDPDNSRaw(t *testing.T, payload []byte) netip.AddrPort {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen udp: %v", err)
	}
	t.Cleanup(func() { _ = pc.Close() })
	go func() {
		buf := make([]byte, consts.DnsMaxMessageSize)
		for {
			_, addr, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			_, _ = pc.WriteTo(payload, addr)
		}
	}()
	return netip.MustParseAddrPort(pc.LocalAddr().String())
}

func TestResolveNetipNXDOMAINStaysNonError(t *testing.T) {
	srv := startUDPDNSRcode(t, dnsmessage.RcodeNameError)

	addrs, err := ResolveNetip(&testNetDialer{}, srv, "example.com", dnsmessage.TypeA, "udp")
	if err != nil {
		t.Fatalf("NXDOMAIN must stay a non-error, got err=%v", err)
	}
	if len(addrs) != 0 {
		t.Fatalf("unexpected addresses: %v", addrs)
	}
}

// startUDPImpostor starts a UDP "server" that answers every query with
// non-DNS bytes: what a REALITY cover-traffic fallback (an HTTP error page
// from the fallback site) or a hijacking middlebox looks like to a probe.
func startUDPImpostor(t *testing.T, payload []byte) netip.AddrPort {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen udp: %v", err)
	}
	t.Cleanup(func() { _ = pc.Close() })
	go func() {
		buf := make([]byte, 1500)
		for {
			_, addr, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			_, _ = pc.WriteTo(payload, addr)
		}
	}()
	return netip.MustParseAddrPort(pc.LocalAddr().String())
}

func TestDnsCheckValidatesResponseHeader(t *testing.T) {
	buildQuery := func() []byte {
		m := new(dnsmessage.Msg)
		m.SetQuestion("example.com.", dnsmessage.TypeA)
		m.RecursionDesired = true
		b, err := m.Pack()
		if err != nil {
			t.Fatalf("pack query: %v", err)
		}
		return b
	}
	d := &testNetDialer{}

	t.Run("genuine reply passes", func(t *testing.T) {
		srv := startUDPDNSRcode(t, dnsmessage.RcodeSuccess)
		if ok, err := DnsCheck(d, srv.String(), "udp", buildQuery()); !ok {
			t.Fatalf("genuine reply must pass, err=%v", err)
		}
	})

	t.Run("http error page fails", func(t *testing.T) {
		srv := startUDPImpostor(t, []byte("HTTP/1.1 400 Bad Request\r\nServer: caddy\r\n\r\n"))
		if ok, err := DnsCheck(d, srv.String(), "udp", buildQuery()); ok {
			t.Fatal("HTTP error page must not pass the check")
		} else if err == nil {
			t.Fatal("expected a validation error")
		}
	})

	t.Run("truncated response fails", func(t *testing.T) {
		srv := startUDPImpostor(t, []byte{0xab, 0xcd})
		if ok, _ := DnsCheck(d, srv.String(), "udp", buildQuery()); ok {
			t.Fatal("truncated response must not pass the check")
		}
	})

	t.Run("id mismatch fails", func(t *testing.T) {
		// A DNS reply whose id does not match the query: genuine format, wrong
		// transaction — the check must still reject it.
		payload, _ := packedAnswer(t, dnsmessage.RcodeSuccess, false)
		payload[0] ^= 0xff
		payload[1] ^= 0xff
		srv := startUDPDNSRaw(t, payload)
		if ok, _ := DnsCheck(d, srv.String(), "udp", buildQuery()); ok {
			t.Fatal("id mismatch must not pass the check")
		}
	})
}
