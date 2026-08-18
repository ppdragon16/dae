/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package sniffing

import (
	"errors"
	"fmt"
	"io"
	"sync"
	"time"

	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/component/sniffing/internal/quicutils"
	"github.com/daeuniverse/outbound/pool"
)

type Sniffer struct {
	// Stream
	r         io.Reader
	dataError error
	readMu    sync.Mutex

	// Common
	sniffed string
	buf     *pool.PooledBuffer

	// Packet
	data         [][]byte
	needMore     bool
	quicNextRead int
	quicCryptos  []*quicutils.CryptoFrameOffset
	// quicLocator is reused across SniffQuic calls to avoid allocating a new
	// LinearLocator each time. It is Reset (not reallocated) on reuse.
	quicLocator *quicutils.LinearLocator
	// quicKeys caches the derived QUIC Initial keys (and their AES/GCM
	// ciphers) for the connection's destination connection id, so repeated
	// Initial packets of the same connection reuse them instead of
	// re-deriving per packet.
	quicKeys *quicutils.Keys
}

func NewStreamSniffer(r io.Reader, timeout time.Duration) *Sniffer {
	buffer := pool.NewPooledBuffer()
	buffer.Grow(AssumedTlsClientHelloMaxLength)
	s := &Sniffer{
		r:   r,
		buf: buffer,
	}
	return s
}

func NewPacketSniffer(data []byte, timeout time.Duration) *Sniffer {
	buffer := pool.NewPooledBuffer()
	buffer.Write(data)
	s := &Sniffer{
		r:    nil,
		buf:  buffer,
		data: [][]byte{buffer.Bytes()},
	}
	return s
}

type sniff func() (d string, err error)

func sniffGroup(sniffs ...sniff) (d string, err error) {
	for _, sniffer := range sniffs {
		d, err = sniffer()
		if err == nil {
			return NormalizeDomain(d), nil
		}
		if err != ErrNotApplicable {
			return "", err
		}
	}
	return "", ErrNotApplicable
}

func (s *Sniffer) SniffTcp() (d string, err error) {
	if s.sniffed != "" {
		return s.sniffed, nil
	}
	defer func() {
		if err == nil {
			s.sniffed = d
		}
	}()
	var oerr error
	defer func() {
		if err != nil {
			err = fmt.Errorf("%w: %w", oerr, err)
		}
	}()
	buf := pool.GetBuffer(consts.EthernetMtu)
	defer pool.PutBuffer(buf)
	for {
		n, rerr := s.r.Read(buf)
		if n > 0 {
			if s.buf != nil {
				s.buf.Write(buf[:n])
			}
		}

		if s.buf.Len() > 0 {
			d, err = sniffGroup(s.SniffTls, s.SniffHttp)
			if err == nil {
				return d, nil
			}
			if !errors.Is(err, ErrNeedMore) {
				return "", err
			}
		}

		if rerr != nil {
			s.dataError = rerr
			return "", rerr
		}

		if s.buf.Len() == 0 {
			return "", ErrNotApplicable
		}

		oerr = err
	}
}

func (s *Sniffer) SniffUdp() (d string, err error) {
	if s.buf == nil {
		return "", ErrNotApplicable
	}
	if s.sniffed != "" {
		return s.sniffed, nil
	}
	defer func() {
		if err == nil {
			s.sniffed = d
		}
	}()

	if s.buf.Len() == 0 {
		return "", ErrNotApplicable
	}

	return sniffGroup(
		s.SniffQuic,
	)
}

func (s *Sniffer) AppendData(data []byte) {
	if s.buf == nil {
		return
	}
	s.needMore = false
	ori := s.buf.Len()
	s.buf.Write(data)
	s.data = append(s.data, s.buf.Bytes()[ori:])
}

func (s *Sniffer) Data() [][]byte {
	return s.data
}

func (s *Sniffer) NeedMore() bool {
	return s.needMore
}

func (s *Sniffer) BufLen() int {
	if s.buf == nil {
		return 0
	}
	return s.buf.Len()
}

func (s *Sniffer) Read(p []byte) (n int, err error) {
	s.readMu.Lock()
	defer s.readMu.Unlock()

	if s.buf != nil {
		if s.buf.Len() > 0 {
			return s.buf.Read(p)
		}
		s.buf.Reset()
		s.buf = nil
	}

	if s.dataError != nil {
		err = s.dataError
		s.dataError = nil
		return 0, err
	}

	return s.r.Read(p)
}

// IsDrained reports whether the sniffer has consumed all buffered sniff data
// and is now just a pass-through to the underlying reader.
func (s *Sniffer) IsDrained() bool {
	return s.buf == nil
}

func (s *Sniffer) Close() (err error) {
	s.readMu.Lock()
	defer s.readMu.Unlock()
	if s.buf != nil {
		s.buf.Reset()
		s.buf = nil
	}
	if s.quicKeys != nil {
		s.quicKeys.Close()
		s.quicKeys = nil
	}
	return nil
}
