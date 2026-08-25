/*
 *  SPDX-License-Identifier: AGPL-3.0-only
 *  Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"errors"
	"io"
	"net"
	"sync"

	"github.com/daeuniverse/quic-go"
)

// ownedEarlyConn pairs a quic.DialEarly result with the caller-owned
// net.PacketConn that quic-go does not close. DialEarly returns an
// EarlyConnection that owns only the QUIC-level state; the socket passed in
// remains the caller's responsibility. Closing the QUIC connection without
// closing the socket leaks one fd per redial, so CloseWithError closes both.
type ownedEarlyConn struct {
	quic.EarlyConnection
	packetConn io.Closer
	closeOnce  sync.Once
	closeErr   error
}

// ownEarlyConnection wraps qc so that closing it also closes packetConn.
// A nil qc or packetConn is returned unwrapped: there is nothing extra to own.
func ownEarlyConnection(qc quic.EarlyConnection, packetConn io.Closer) quic.EarlyConnection {
	if qc == nil || packetConn == nil {
		return qc
	}
	return &ownedEarlyConn{EarlyConnection: qc, packetConn: packetConn}
}

func (c *ownedEarlyConn) CloseWithError(code quic.ApplicationErrorCode, reason string) error {
	c.closeOnce.Do(func() {
		c.closeErr = c.EarlyConnection.CloseWithError(code, reason)
		if err := c.packetConn.Close(); err != nil && c.closeErr == nil && !isBenignConnCloseError(err) {
			c.closeErr = err
		}
	})
	return c.closeErr
}

// isBenignConnCloseError reports errors that are expected when closing an
// already-closed socket and should not override a real QUIC close error.
func isBenignConnCloseError(err error) bool {
	return err == nil || errors.Is(err, net.ErrClosed) || errors.Is(err, io.EOF)
}
