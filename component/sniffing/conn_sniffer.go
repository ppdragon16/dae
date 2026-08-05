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
