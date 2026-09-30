package control

import (
	"errors"
	"net"
	"testing"
	"time"

	"github.com/daeuniverse/dae/component/sniffing"
	"github.com/daeuniverse/outbound/netproxy"
)

// Wrapper capability parity gate.
//
// Every type that wraps a net.Conn and is handed to the relay must either
// forward the relay's optional capabilities itself or be registered below
// with a documented reason. The one optional capability this tree defines is
// netproxy.CloseWriter (half-close); a wrapper that embeds net.Conn silently
// loses it, and the relay then falls back to the read-deadline half-close —
// a behaviour regression that never shows up at compile time. koutbound
// added a reflection-driven gate for exactly this failure class; this is the
// ppdn-side equivalent, scoped to the wrappers this module owns.
//
// When adding a new wrapper: construct it here and require parity, or
// register it in the exceptions list with the reason.

type parityStubConn struct {
	net.Conn
	halfClosed bool
	err        error
}

func (c *parityStubConn) CloseWrite() error {
	c.halfClosed = true
	return c.err
}

// parityPlainConn deliberately does NOT implement CloseWriter: it models the
// innermost conns that cannot half-close (h2 streams, pipes).
type parityPlainConn struct {
	net.Conn
}

// parityWrapperCase registers one wrapper with the capability contract it
// must uphold.
type parityWrapperCase struct {
	name string
	// build returns the wrapper over a CloseWriter-capable stub.
	build func(stub *parityStubConn) net.Conn
	// requireCloseWriter: the wrapper must implement netproxy.CloseWriter
	// and deliver CloseWrite to the inner conn.
	requireCloseWriter bool
	// reason documents the contract when requireCloseWriter is false.
	reason string
}

var parityWrapperCases = []parityWrapperCase{
	{
		name:               "TrafficLogConn",
		build:              func(stub *parityStubConn) net.Conn { return NewTrafficLogConn(stub, nil, nil) },
		requireCloseWriter: true,
	},
	{
		name: "ConnSniffer (CloseWriter-capable inner)",
		build: func(stub *parityStubConn) net.Conn {
			return sniffing.NewConnSniffer(stub, time.Second)
		},
		requireCloseWriter: true,
	},
	{
		name: "CloseWriteConn",
		build: func(stub *parityStubConn) net.Conn {
			return netproxy.CloseWriteConn{Conn: stub, CloseWriter: stub}
		},
		requireCloseWriter: true,
	},
	{
		name: "ConnSniffer (plain inner)",
		build: func(stub *parityStubConn) net.Conn {
			return sniffing.NewConnSniffer(&parityPlainConn{Conn: stub.Conn}, time.Second)
		},
		requireCloseWriter: false,
		// Documented degradation: without a CloseWriter inner, the sniffer
		// must NOT fake the capability (the typed-nil/unsupported trap);
		// relayDirection takes its read-deadline fallback instead.
		reason: "half-close is impossible without a CloseWriter inner; the relay's ok-form fallback covers it",
	},
}

func TestWrapperCapabilityParity(t *testing.T) {
	for _, tc := range parityWrapperCases {
		t.Run(tc.name, func(t *testing.T) {
			stub := &parityStubConn{}
			wrapped := tc.build(stub)

			if _, ok := wrapped.(net.Conn); !ok {
				t.Fatalf("%s does not satisfy net.Conn", tc.name)
			}

			cw, ok := wrapped.(netproxy.CloseWriter)
			if tc.requireCloseWriter {
				if !ok {
					t.Fatalf("%s hides CloseWrite: it embeds net.Conn without forwarding "+
						"netproxy.CloseWriter. Add a CloseWrite forward, or register an "+
						"exception with a reason in parityWrapperCases.", tc.name)
				}
				wantErr := errors.New("parity probe")
				stub.err = wantErr
				if err := cw.CloseWrite(); !errors.Is(err, wantErr) {
					t.Fatalf("%s.CloseWrite() = %v, want the inner error", tc.name, err)
				}
				if !stub.halfClosed {
					t.Fatalf("%s.CloseWrite() did not reach the inner conn", tc.name)
				}
			} else {
				if ok {
					t.Fatalf("%s unexpectedly implements CloseWriter; update its contract: %s",
						tc.name, tc.reason)
				}
				if tc.reason == "" {
					t.Fatalf("%s is registered without a reason", tc.name)
				}
			}
		})
	}
}
