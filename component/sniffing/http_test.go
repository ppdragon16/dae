/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package sniffing

import (
	"bytes"
	"errors"
	"testing"
	"time"
)

// TestSniffHttpNeedsMoreOnSplitRequestLine pins the retry contract at the
// request line: a method-validated buffer without an LF is a request line split
// across reads, not a final verdict. (Port of kdae ca97821b.)
func TestSniffHttpNeedsMoreOnSplitRequestLine(t *testing.T) {
	sniffer := NewPacketSniffer([]byte("GET /path HTTP/1.1\r"), 50*time.Millisecond)
	_, err := sniffer.SniffHttp()
	if !errors.Is(err, ErrNeedMore) {
		t.Fatalf("err = %v, want ErrNeedMore for a split request line", err)
	}
	sniffer.AppendData([]byte("\nHost: example.com\r\n\r\n"))
	d, err := sniffer.SniffHttp()
	if err != nil {
		t.Fatalf("SniffHttp after the rest arrived: %v", err)
	}
	if d != "example.com" {
		t.Fatalf("domain = %q, want example.com", d)
	}
}

// TestSniffHttpNeedsMoreOnSplitHostValue pins the same retry contract one line
// down: when the read boundary falls inside the Host value, the truncated line
// must not be accepted as complete — that would route by a silently truncated
// domain (here "exam") instead of waiting for the rest of the header block.
func TestSniffHttpNeedsMoreOnSplitHostValue(t *testing.T) {
	sniffer := NewPacketSniffer([]byte("GET /path HTTP/1.1\r\nHost: exam"), 50*time.Millisecond)
	_, err := sniffer.SniffHttp()
	if !errors.Is(err, ErrNeedMore) {
		t.Fatalf("err = %v, want ErrNeedMore for a Host value split across reads", err)
	}
}

// TestSniffHttpNeedsMoreUntilHeaderBlockEnds: complete lines without the
// end-of-headers blank line are not a final verdict either — the Host may
// arrive in a later header line.
func TestSniffHttpNeedsMoreUntilHeaderBlockEnds(t *testing.T) {
	sniffer := NewPacketSniffer([]byte("GET /path HTTP/1.1\r\nAccept: text/plain\r\n"), 50*time.Millisecond)
	_, err := sniffer.SniffHttp()
	if !errors.Is(err, ErrNeedMore) {
		t.Fatalf("err = %v, want ErrNeedMore for an unfinished header block", err)
	}
}

// TestSniffHttpGivesUpAtBufferCap: LF-free header bytes are bounded in space;
// beyond the cap the sniff ends instead of buffering without limit. The
// deadline bounds the wait in time; this bounds it structurally. The cap only
// bites where accumulation would continue — an oversized-but-parseable header
// block still resolves its Host.
func TestSniffHttpGivesUpAtBufferCap(t *testing.T) {
	head := append([]byte("GET /path HTTP/1.1\r\nX-Pad: "), bytes.Repeat([]byte{'a'}, sniffHTTPMaxBufferedSize)...)
	sniffer := NewPacketSniffer(head, 50*time.Millisecond)
	_, err := sniffer.SniffHttp()
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("err = %v, want ErrNotFound past the buffered-size cap", err)
	}

	// A header block larger than the cap whose Host line sits early is still
	// sniffed: the bound is on further accumulation, not on the buffered size
	// of already-received, parseable headers.
	big := append([]byte("GET /path HTTP/1.1\r\nHost: early.example\r\nX-Pad: "),
		bytes.Repeat([]byte{'b'}, sniffHTTPMaxBufferedSize)...)
	big = append(big, "\r\n\r\n"...)
	sniffer = NewPacketSniffer(big, 50*time.Millisecond)
	d, err := sniffer.SniffHttp()
	if err != nil {
		t.Fatalf("oversized-but-parseable header block: %v", err)
	}
	if d != "early.example" {
		t.Fatalf("domain = %q, want early.example", d)
	}
}
