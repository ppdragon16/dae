/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package sniffing

import (
	"errors"
	"net"
	"time"

	"github.com/daeuniverse/outbound/netproxy"
)

type ConnSnifferInterface interface {
	net.Conn
	SniffTcp() (string, error)
	// SniffProgress reports the accumulated byte count and a snapshot of the
	// leading bytes, so a failed sniff can be reported with what it saw.
	SniffProgress() (int, []byte)
}

type ConnSniffer struct {
	net.Conn
	*Sniffer
}

type ConnSnifferCloseWriter struct {
	*ConnSniffer
}

func (c *ConnSnifferCloseWriter) CloseWrite() error {
	return c.Conn.(netproxy.CloseWriter).CloseWrite()
}

func NewConnSniffer(conn net.Conn, timeout time.Duration) ConnSnifferInterface {
	s := &ConnSniffer{
		Conn:    conn,
		Sniffer: NewStreamSniffer(conn, timeout),
	}
	if _, ok := conn.(netproxy.CloseWriter); ok {
		return &ConnSnifferCloseWriter{
			ConnSniffer: s,
		}
	}
	return s
}

func (s *ConnSniffer) Read(p []byte) (n int, err error) {
	// Snapshot the sniffer pointer once to avoid racing with Close() which
	// may nil it out concurrently.
	sniffer := s.Sniffer
	if sniffer == nil {
		return s.Conn.Read(p)
	}
	n, err = sniffer.Read(p)
	// Once the sniffer has served all buffered sniff data, it becomes a
	// useless pass-through — detach it so subsequent reads hit s.Conn
	// directly without overhead.
	if sniffer.IsDrained() {
		sniffer.Close()
		s.Sniffer = nil
	}
	return
}

func (s *ConnSniffer) Close() error {
	// Snapshot the sniffer pointer once to avoid racing with Read() which
	// may nil it out concurrently (causing a nil-pointer dereference).
	if sniffer := s.Sniffer; sniffer != nil {
		return errors.Join(s.Conn.Close(), sniffer.Close())
	}
	return s.Conn.Close()
}

// WatchOnlyConnSniffer relays the connection untouched and classifies the
// stream on the way out: every read's bytes are accumulated and parsed until a
// verdict is reached, and the verdict -- the sniffed domain, empty when none
// was learned -- is reported to onDomain exactly once (also when the
// connection closes before a verdict). It is observability only: the domain
// never influences routing or the dial target.
type WatchOnlyConnSniffer struct {
	net.Conn
	sniffer  *Sniffer
	onDomain func(domain string)
	decided  bool
}

// NewWatchOnlyConnSniffer returns a conn that relays immediately and
// classifies the stream on its reads. When the underlay supports a
// half-close, the returned conn keeps that capability (a wrapper that faked
// CloseWrite would tell the relay the peer received a FIN it never got).
func NewWatchOnlyConnSniffer(conn net.Conn, timeout time.Duration, onDomain func(domain string)) *WatchOnlyConnSniffer {
	w := &WatchOnlyConnSniffer{
		Conn:     conn,
		sniffer:  NewStreamSniffer(conn, timeout),
		onDomain: onDomain,
	}
	if w.onDomain == nil {
		w.onDomain = func(string) {}
	}
	return w
}

func (w *WatchOnlyConnSniffer) Read(p []byte) (n int, err error) {
	n, err = w.Conn.Read(p)
	if w.decided || n == 0 {
		return n, err
	}
	w.sniffer.AppendTcpData(p[:n])
	if d, serr := w.sniffer.SniffTcpData(); !errors.Is(serr, ErrNeedMore) {
		w.decided = true
		w.onDomain(d) // empty on a terminal verdict
	}
	return n, err
}

func (w *WatchOnlyConnSniffer) Close() error {
	if !w.decided {
		w.decided = true
		w.onDomain("")
	}
	return w.Conn.Close()
}
