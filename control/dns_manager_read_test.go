/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"bytes"
	"encoding/binary"
	"io"
	"net"
	"testing"
	"time"

	"github.com/daeuniverse/dae/common/consts"
)

// cannedConn serves a fixed byte slice through Read and discards writes, so a
// DnsManager read path can be driven without an upstream.
type cannedConn struct {
	data []byte
	off  int
}

func (c *cannedConn) Read(p []byte) (int, error) {
	if c.off >= len(c.data) {
		return 0, io.EOF
	}
	n := copy(p, c.data[c.off:])
	c.off += n
	return n, nil
}
func (c *cannedConn) Write(p []byte) (int, error)      { return len(p), nil }
func (c *cannedConn) Close() error                     { return nil }
func (c *cannedConn) LocalAddr() net.Addr              { return &net.UDPAddr{} }
func (c *cannedConn) RemoteAddr() net.Addr             { return &net.UDPAddr{} }
func (c *cannedConn) SetDeadline(time.Time) error      { return nil }
func (c *cannedConn) SetReadDeadline(time.Time) error  { return nil }
func (c *cannedConn) SetWriteDeadline(time.Time) error { return nil }

// TestDnsManagerReadUDPBufferHoldsTheClampedUpstreamMaximum pins the coupling
// behind option B: the upstream query is clamped to dnsUDPPayloadCap before it
// is sent (dnsClampUDPSize), so an MTU-sized UDP read buffer can hold every
// answer a plain UDP upstream may legitimately return. Anything larger is
// expected to arrive over TCP via the TC bit, where the message is
// length-framed and read whole — which is why the clamp and this buffer must
// be changed together.
func TestDnsManagerReadUDPBufferHoldsTheClampedUpstreamMaximum(t *testing.T) {
	if dnsUDPPayloadCap > consts.EthernetMtu {
		t.Fatalf("dnsUDPPayloadCap (%d) exceeds the MTU-sized UDP read buffer (%d): "+
			"an upstream answer at the cap would be truncated again",
			dnsUDPPayloadCap, consts.EthernetMtu)
	}
	resp := bytes.Repeat([]byte{0xAB}, dnsUDPPayloadCap)
	m := &DnsManager{conn: &cannedConn{data: resp}}

	got, err := m.read()
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if len(got) != len(resp) {
		t.Fatalf("read %d bytes, want %d: the buffer no longer holds a clamped answer",
			len(got), len(resp))
	}
	if !bytes.Equal(got, resp) {
		t.Fatal("payload mismatch")
	}
}

// TestDnsManagerReadTCPKeepsFullResponse pins the upstream TCP path, which
// used to reject any framed message longer than EthernetMtu (1500) even though
// the two-byte length field allows 65535.
func TestDnsManagerReadTCPKeepsFullResponse(t *testing.T) {
	resp := bytes.Repeat([]byte{0xCD}, 4096)
	framed := make([]byte, 2+len(resp))
	binary.BigEndian.PutUint16(framed[:2], uint16(len(resp)))
	copy(framed[2:], resp)

	m := &DnsManager{conn: &cannedConn{data: framed}, stream: true}

	got, err := m.read()
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if len(got) != len(resp) {
		t.Fatalf("read %d bytes, want %d", len(got), len(resp))
	}
	if !bytes.Equal(got, resp) {
		t.Fatal("payload mismatch")
	}
}
