package control

import (
	"bytes"
	"net"
	"net/netip"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/daeuniverse/dae/pkg/logger/fastlog"
	log "github.com/sirupsen/logrus"
)

// TestSniffTimeoutCause pins the three shapes a sniffing timeout can report.
// The mapping is exact rather than heuristic: a TLS record that never completed
// always starts with the handshake content type (the parser only asks for more
// after reading that header), an HTTP header that stalled always starts with a
// printable method, and "no first byte" means the peer never sent anything --
// remote-first protocols, preconnects and probes, which relay by design.
func TestSniffTimeoutCause(t *testing.T) {
	cases := []struct {
		name      string
		bytesRead int
		head      []byte
		wantCause fastlog.SniffTimeoutCause
		wantLen   int
		wantGot   int
	}{
		{"no first byte", 0, nil, fastlog.SniffTimeoutNoFirstByte, 0, 0},
		{"count without head", 5, nil, fastlog.SniffTimeoutNoFirstByte, 0, 0},
		{
			// Handshake content type, TLS 1.0 record version, declared length 512.
			name: "partial TLS record", bytesRead: 100,
			head:      []byte{0x16, 0x03, 0x01, 0x02, 0x00, 0x01, 0x00, 0x01},
			wantCause: fastlog.SniffTimeoutPartialTLS, wantLen: 512, wantGot: 95,
		},
		{
			// Defensive: a handshake byte with less than a record header. The
			// parser cannot produce this (it needs five bytes first), but the
			// classifier must still not read past the snapshot.
			name: "handshake byte, short head", bytesRead: 3,
			head:      []byte{0x16, 0x03, 0x01},
			wantCause: fastlog.SniffTimeoutPartialTLS, wantLen: 0, wantGot: 3,
		},
		{
			name: "partial HTTP header", bytesRead: 27,
			head:      []byte("GET / HTTP/1.1\r\nHost: exa"),
			wantCause: fastlog.SniffTimeoutPartialHTTP,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cause, recordLen, recordGot := sniffTimeoutCause(tc.bytesRead, tc.head)
			if cause != tc.wantCause {
				t.Fatalf("cause = %v, want %v", cause, tc.wantCause)
			}
			if recordLen != tc.wantLen || recordGot != tc.wantGot {
				t.Fatalf("record = (%d, %d), want (%d, %d)", recordLen, recordGot, tc.wantLen, tc.wantGot)
			}
		})
	}
}

// TestSniffTimeoutFieldsFallback pins the logrus path taken where fastlog is
// off: same classification, same values, and the fields that must not appear.
func TestSniffTimeoutFieldsFallback(t *testing.T) {
	src := netip.MustParseAddrPort("192.0.2.10:34567")
	dst := netip.MustParseAddrPort("198.51.100.20:443")
	elapsed := 300 * time.Millisecond

	t.Run("no first byte", func(t *testing.T) {
		cause, recordLen, recordGot := sniffTimeoutCause(0, nil)
		fields := sniffTimeoutFields(src, dst, cause, 0, recordLen, recordGot, nil, elapsed)
		if fields["cause"] != "no first byte" {
			t.Fatalf("cause = %v", fields["cause"])
		}
		if _, ok := fields["head"]; ok {
			t.Fatal("no bytes arrived, so there must be no head snapshot")
		}
		if _, ok := fields["record_len"]; ok {
			t.Fatal("record_len only applies to a TLS record")
		}
		if fields["src"] != src.String() || fields["dst"] != dst.String() {
			t.Fatalf("src/dst = %v/%v, want %v/%v", fields["src"], fields["dst"], src, dst)
		}
		if fields["bytes"] != 0 || fields["elapsed"] != "300ms" {
			t.Fatalf("bytes/elapsed = %v/%v, want 0/300ms", fields["bytes"], fields["elapsed"])
		}
	})

	t.Run("partial TLS record", func(t *testing.T) {
		head := []byte{0x16, 0x03, 0x01, 0x02, 0x00, 0x01, 0x00, 0x01}
		cause, recordLen, recordGot := sniffTimeoutCause(100, head)
		fields := sniffTimeoutFields(src, dst, cause, 100, recordLen, recordGot, head, elapsed)
		if fields["cause"] != "partial TLS record" {
			t.Fatalf("cause = %v", fields["cause"])
		}
		if fields["record_len"] != 512 || fields["record_got"] != 95 {
			t.Fatalf("record = (%v, %v), want (512, 95)", fields["record_len"], fields["record_got"])
		}
		if fields["head"] != "16 03 01 02 00 01 00 01" {
			t.Fatalf("head = %v", fields["head"])
		}
	})

	t.Run("partial HTTP header", func(t *testing.T) {
		head := []byte("GET / HTTP/1.1\r\nHost: exa")
		cause, recordLen, recordGot := sniffTimeoutCause(27, head)
		fields := sniffTimeoutFields(src, dst, cause, 27, recordLen, recordGot, head, elapsed)
		if fields["cause"] != "partial HTTP header" {
			t.Fatalf("cause = %v", fields["cause"])
		}
		if _, ok := fields["record_len"]; ok {
			t.Fatal("record_len must not appear for a header block")
		}
	})
}

// TestSniffAbortFields pins the abort report: the location and the wait are
// always there, and bytes/head say whether the peer had spoken before it went
// away -- the difference between "it never sent anything" and "it died
// mid-handshake".
func TestSniffAbortFields(t *testing.T) {
	src := netip.MustParseAddrPort("192.0.2.10:34567")
	dst := netip.MustParseAddrPort("198.51.100.20:443")
	elapsed := 12 * time.Millisecond

	t.Run("went away before sending", func(t *testing.T) {
		fields := sniffAbortFields(src, dst, 0, nil, elapsed)
		if fields["src"] != src.String() || fields["dst"] != dst.String() {
			t.Fatalf("src/dst = %v/%v, want %v/%v", fields["src"], fields["dst"], src, dst)
		}
		if fields["bytes"] != 0 || fields["elapsed"] != "12ms" {
			t.Fatalf("bytes/elapsed = %v/%v, want 0/12ms", fields["bytes"], fields["elapsed"])
		}
		if _, ok := fields["head"]; ok {
			t.Fatal("no bytes arrived, so there must be no head snapshot")
		}
	})

	t.Run("died mid-handshake", func(t *testing.T) {
		head := []byte{0x16, 0x03, 0x01, 0x02, 0x00}
		fields := sniffAbortFields(src, dst, 100, head, elapsed)
		if fields["bytes"] != 100 {
			t.Fatalf("bytes = %v, want 100", fields["bytes"])
		}
		if fields["head"] != "16 03 01 02 00" {
			t.Fatalf("head = %v", fields["head"])
		}
	})
}

// TestReportSniffAbortIsReachable pins that the abort report actually emits at
// the debug level, with the error and the sniff progress -- the path used to
// return without any line at all.
func TestReportSniffAbortIsReachable(t *testing.T) {
	var buf bytes.Buffer
	prevOut, prevLevel := log.StandardLogger().Out, log.GetLevel()
	log.SetOutput(&buf)
	log.SetLevel(log.DebugLevel)
	t.Cleanup(func() {
		log.SetOutput(prevOut)
		log.SetLevel(prevLevel)
	})

	err := &net.OpError{Op: "read", Net: "tcp", Err: syscall.ECONNRESET}
	reportSniffAbort(
		netip.MustParseAddrPort("192.0.2.10:34567"),
		netip.MustParseAddrPort("198.51.100.20:443"),
		err, 100, []byte{0x16, 0x03, 0x01}, 12*time.Millisecond,
	)

	output := buf.String()
	t.Logf("abort line: %s", output)
	for _, want := range []string{
		"Sniffing aborted",
		`src="192.0.2.10:34567"`,
		`dst="198.51.100.20:443"`,
		"bytes=100",
		"elapsed=12ms",
		`head="16 03 01"`,
		"connection reset by peer",
	} {
		if !strings.Contains(output, want) {
			t.Fatalf("output missing %q: %s", want, output)
		}
	}
}
