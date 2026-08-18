/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package sniffing

import (
	"encoding/binary"
	"errors"
	"io/fs"

	"github.com/daeuniverse/dae/common"
	"github.com/daeuniverse/dae/component/sniffing/internal/quicutils"
	"github.com/daeuniverse/outbound/pool"
)

const (
	QuicFlag_PacketNumberLength = iota
	QuicFlag_PacketNumberLength1
	QuicFlag_Reserved
	QuicFlag_Reserved1
	QuicFlag_LongPacketType
	QuicFlag_LongPacketType1
	QuicFlag_FixedBit
	QuicFlag_HeaderForm
)
const (
	QuicFlag_HeaderForm_LongHeader  = 1
	QuicFlag_LongPacketType_Initial = 0
)

type QuicReassemblePolicy int

const (
	QuicReassemblePolicy_ReassembleCryptoToBytesFromPool QuicReassemblePolicy = iota
	QuicReassemblePolicy_LinearLocator
	QuicReassemblePolicy_Slow
)

func (s *Sniffer) SniffQuic() (d string, err error) {
	nextBlock := s.buf.Bytes()[s.quicNextRead:]

	// Consume as many consecutive QUIC blocks as we can find.
	for len(nextBlock) > 0 {
		nextBlock, err = s.sniffQuicBlock(nextBlock)
		if err != nil {
			if errors.Is(err, fs.ErrClosed) {
				return "", ErrNotFound
			}
			// ErrNotApplicable (not a QUIC block) or any other error:
			// stop consuming. The block may still be QUIC — we just
			// can't parse this particular payload.
			break
		}
	}

	// If no crypto frames were found (in this call or prior calls),
	// this isn't QUIC traffic.
	if len(s.quicCryptos) == 0 {
		return "", ErrNotApplicable
	}

	// Is quic.
	s.quicNextRead = s.buf.Len()
	// Reuse the per-Sniffer LinearLocator across SniffQuic calls instead of
	// allocating a new one each time (NewLinearLocator was a leading QUIC
	// allocation). Reset repoints it at the current crypto frame offsets.
	if s.quicLocator == nil {
		s.quicLocator = quicutils.NewLinearLocator(s.quicCryptos)
	} else {
		s.quicLocator.Reset(s.quicCryptos)
	}
	sni, err := extractSniFromTls(s.quicLocator)
	if err != nil {
		// Determine whether more data might help.
		if errors.Is(err, quicutils.ErrMissingCrypto) {
			// CRYPTO frames have gaps — more Initial packets may fill them.
			// Allow up to ~3 full-size Initial packets before giving up.
			if s.quicNextRead < 3600 {
				s.needMore = true
			}
		} else if s.quicNextRead < 1500 {
			// Other error and we haven't read much data yet.
			s.needMore = true
		}
		return "", ErrNotFound
	}
	return sni, nil
}

func (s *Sniffer) sniffQuicBlock(buf []byte) (next []byte, err error) {
	// QUIC: A UDP-Based Multiplexed and Secure Transport
	// https://datatracker.ietf.org/doc/html/rfc9000#name-initial-packet
	const dstConnIdPos = 6
	boundary := dstConnIdPos
	if len(buf) < boundary {
		return nil, ErrNotApplicable
	}
	// Check flag.
	// Long header: 4 bits masked
	// High 4 bits are not protected, so we can access QuicFlag_HeaderForm and QuicFlag_LongPacketType without decryption.
	protectedFlag := buf[0]
	if ((protectedFlag >> QuicFlag_HeaderForm) & 0b11) != QuicFlag_HeaderForm_LongHeader {
		return nil, ErrNotApplicable
	}
	if ((protectedFlag >> QuicFlag_LongPacketType) & 0b11) != QuicFlag_LongPacketType_Initial {
		return nil, ErrNotApplicable
	}

	// Skip version.

	destConnIdLength := int(buf[boundary-1])
	boundary += destConnIdLength + 1 // +1 because next field has 1B length
	if len(buf) < boundary {
		return nil, ErrNotApplicable
	}
	destConnId := buf[dstConnIdPos : dstConnIdPos+destConnIdLength]

	srcConnIdLength := int(buf[boundary-1])
	boundary += srcConnIdLength + quicutils.MaxVarintLen64 // The next fields may have quic.MaxVarintLen64 bytes length
	if len(buf) < boundary {
		return nil, ErrNotApplicable
	}
	tokenLength, n, err := quicutils.BigEndianUvarint(buf[boundary-quicutils.MaxVarintLen64:])
	if err != nil {
		return nil, ErrNotApplicable
	}
	boundary = boundary - quicutils.MaxVarintLen64 + n      // Correct boundary.
	boundary += int(tokenLength) + quicutils.MaxVarintLen64 // Next fields may have quic.MaxVarintLen64 bytes length
	if len(buf) < boundary {
		return nil, ErrNotApplicable
	}
	// https://datatracker.ietf.org/doc/html/rfc9000#name-variable-length-integer-enc
	length, n, err := quicutils.BigEndianUvarint(buf[boundary-quicutils.MaxVarintLen64:])
	if err != nil {
		return nil, ErrNotApplicable
	}
	boundary = boundary - quicutils.MaxVarintLen64 + n // Correct boundary.
	blockEnd := boundary + int(length)
	if len(buf) < blockEnd {
		return nil, ErrNotApplicable
	}
	boundary += quicutils.MaxPacketNumberLength
	if len(buf) < boundary {
		return nil, ErrNotApplicable
	}
	header := buf[:boundary]
	// Decrypt protected Packets.
	// https://datatracker.ietf.org/doc/html/rfc9000#packet-protected

	// This function will modify the packet in place, thus we should save the first byte and MaxPacketNumberLength
	// and recover it later.
	firstByte := header[0]
	rawPacketNumber := pool.GetBuffer(quicutils.MaxPacketNumberLength)
	defer pool.PutBuffer(rawPacketNumber)
	copy(rawPacketNumber, header[boundary-quicutils.MaxPacketNumberLength:])
	defer func() {
		header[0] = firstByte
		copy(header[boundary-quicutils.MaxPacketNumberLength:], rawPacketNumber)
	}()

	// Derive or reuse the keys for this destination connection id. Repeated
	// Initial packets of the same connection share the same DCID (and thus the
	// same keys), so caching them avoids re-running HKDF and rebuilding the
	// AES/GCM ciphers for every packet.
	version, err := quicutils.ParseVersion(binary.BigEndian.Uint32(header[1:]))
	if err != nil {
		return nil, ErrNotApplicable
	}
	if !s.quicKeys.Matches(destConnId, version) {
		if s.quicKeys != nil {
			s.quicKeys.Close()
		}
		s.quicKeys, err = quicutils.NewKeys(destConnId, version, common.NewGcm)
		if err != nil {
			s.quicKeys = nil
			return nil, ErrNotApplicable
		}
	}

	plaintext, err := quicutils.DecryptQuic_(s.quicKeys, header, blockEnd)
	if err != nil {
		return nil, ErrNotApplicable
	}
	// The crypto frames slice the plaintext buffer, so it can only be released
	// when the sniffer closes. Track it here for Close to return to the pool.
	s.plaintextBufs = append(s.plaintextBufs, plaintext)
	// Now, we confirm it is exact a quic frame.
	// After here, we should not return NotApplicableError.
	// And we should return nextFrame.
	if s.quicCryptos, err = quicutils.ReassembleCryptos(s.quicCryptos, plaintext); err != nil {
		if errors.Is(err, fs.ErrClosed) {
			return nil, err
		}
		return buf[blockEnd:], ErrNotApplicable
	}
	return buf[blockEnd:], nil
}
