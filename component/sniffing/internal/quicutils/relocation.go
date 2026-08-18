/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package quicutils

import (
	"fmt"
	"io/fs"
	"sort"
)

var (
	ErrUnknownFrameType = fmt.Errorf("unknown frame type")
	ErrOutOfRange       = fmt.Errorf("index out of range")
)

const (
	Quic_FrameType_Padding          = 0
	Quic_FrameType_Ping             = 1
	Quic_FrameType_Crypto           = 6
	Quic_FrameType_ConnectionClose  = 0x1c
	Quic_FrameType_ConnectionClose2 = 0x1d
)

type CryptoFrameOffset struct {
	UpperAppOffset int
	// Offset of data in quic payload.
	Data []byte
}

func ReassembleCryptos(offsets []*CryptoFrameOffset, newPayload []byte) (newOffsets []*CryptoFrameOffset, err error) {
	oldLen := len(offsets)
	var frameSize int
	var offset *CryptoFrameOffset
	var boundary int
	// Extract crypto frames.
	for iNextFrame := 0; iNextFrame < len(newPayload); iNextFrame += frameSize {
		offset, frameSize, err = ExtractCryptoFrameOffset(newPayload[iNextFrame:], iNextFrame)
		if err != nil {
			return nil, err
		}
		if offset == nil {
			continue
		}
		offsets = append(offsets, offset)
		if offset.UpperAppOffset+len(offset.Data) > boundary {
			boundary = offset.UpperAppOffset + len(offset.Data)
		}
	}
	if len(offsets) <= 1 {
		// With zero or one frame there is nothing to sort or merge; return as-is
		// to skip the merged-slice allocation and the reflect-based sort.Slice
		// swapper. This is the common case for a QUIC Initial whose ClientHello
		// fits in a single CRYPTO frame.
		return offsets, nil
	}

	// Sort the new part.
	newPart := offsets[oldLen:]
	sort.Slice(newPart, func(i, j int) bool {
		return newPart[i].UpperAppOffset < newPart[j].UpperAppOffset
	})

	// Insertion sort.
	for i := oldLen; i < len(offsets); i++ {
		item := offsets[i]
		j := i - 1
		for ; j >= 0; j-- {
			if item.UpperAppOffset < offsets[j].UpperAppOffset {
				offsets[j+1] = offsets[j]
			} else {
				if offsets[j+1] != item {
					offsets[j+1] = item
				}
				break
			}
		}
		if j < 0 {
			offsets[0] = item
		}
	}
	return offsets, nil
}

func ExtractCryptoFrameOffset(remainder []byte, transportOffset int) (offset *CryptoFrameOffset, frameSize int, err error) {
	if len(remainder) == 0 {
		return nil, 0, fmt.Errorf("frame has no length: %w", ErrOutOfRange)
	}
	frameType, nextField, err := BigEndianUvarint(remainder)
	if err != nil {
		return nil, 0, err
	}
	switch frameType {
	case Quic_FrameType_Ping:
		return nil, nextField, nil
	case Quic_FrameType_Padding:
		for ; nextField < len(remainder) && remainder[nextField] == 0; nextField++ {
		}
		return nil, nextField, nil
	case Quic_FrameType_Crypto:
		offset, n, err := BigEndianUvarint(remainder[nextField:])
		if err != nil {
			return nil, 0, err
		}
		nextField += n

		length, n, err := BigEndianUvarint(remainder[nextField:])
		if err != nil {
			return nil, 0, err
		}
		nextField += n

		return &CryptoFrameOffset{
			UpperAppOffset: int(offset),
			Data:           remainder[nextField : nextField+int(length)],
		}, nextField + int(length), nil
	case Quic_FrameType_ConnectionClose, Quic_FrameType_ConnectionClose2:
		return nil, 0, fmt.Errorf("connection closed: %w", fs.ErrClosed)
	default:
		// Unknown frame type (e.g. ACK, STREAM, etc.) — skip the
		// remainder of the payload rather than failing. Failing here
		// would reject the entire QUIC packet as non-QUIC, breaking
		// sniffing when Initial packets carry non-CRYPTO frames.
		return nil, len(remainder), nil
	}
}

var (
	ErrMissingCrypto = fmt.Errorf("missing crypto frame")
)

type Locator interface {
	Range(i, j int) ([]byte, error)
	At(i int) (byte, error)
	Len() int
	Bytes() ([]byte, error)
}

// LinearLocator only searches forward and have no boundary check.
type LinearLocator struct {
	length    int
	iOuter    int
	baseEnd   int
	baseStart int
	baseData  []byte
	o         []*CryptoFrameOffset
}

func NewLinearLocator(o []*CryptoFrameOffset) *LinearLocator {
	l := &LinearLocator{}
	l.Reset(o)
	return l
}

// Reset reinitializes an existing *LinearLocator for a new set of crypto frame
// offsets, avoiding the allocation that NewLinearLocator performs. Callers that
// retain the locator across sniffing calls (e.g. a pooled Sniffer) should use
// this instead of constructing a new locator each time.
func (l *LinearLocator) Reset(o []*CryptoFrameOffset) {
	l.iOuter = 0
	if len(o) == 0 {
		l.length = 0
		l.baseData = nil
		l.baseStart = 0
		l.baseEnd = 0
		l.o = nil
		return
	}
	// The reassembled crypto spans up to the maximum frame end, not just the
	// last frame's end: overlapping or contained frames (e.g. retransmitted
	// CRYPTO) can otherwise make the locator report a too-small length and
	// truncate the reassembled ClientHello.
	length := 0
	for _, frame := range o {
		if end := frame.UpperAppOffset + len(frame.Data); end > length {
			length = end
		}
	}
	l.length = length
	l.baseData = o[0].Data
	l.baseStart = o[0].UpperAppOffset
	l.baseEnd = o[0].UpperAppOffset + len(o[0].Data)
	l.o = o
}

// advance moves to the next frame that extends coverage beyond baseEnd,
// skipping contained/overlapping/retransmitted frames whose data range is
// already covered. It reports whether the new frame is contiguous with the
// previous coverage (no gap).
func (l *LinearLocator) advance() (contiguous bool, err error) {
	previousEnd := l.baseEnd
	for l.iOuter+1 < len(l.o) {
		next := l.o[l.iOuter+1]
		nextStart := next.UpperAppOffset
		nextEnd := nextStart + len(next.Data)
		l.iOuter++
		if nextEnd <= l.baseEnd {
			continue
		}
		l.baseData = next.Data
		l.baseStart = nextStart
		l.baseEnd = nextEnd
		return nextStart <= previousEnd, nil
	}
	return false, ErrMissingCrypto
}

func (l *LinearLocator) relocate(i int) error {
	// Relocate ll.iOuter.
	for i >= l.baseEnd {
		if _, err := l.advance(); err != nil {
			return err
		}
	}
	if i < l.baseStart {
		return ErrMissingCrypto
	}
	return nil
}

func (l *LinearLocator) Range(i, j int) ([]byte, error) {
	if i == j {
		return []byte{}, nil
	}
	if len(l.o) == 0 {
		return nil, ErrMissingCrypto
	}
	size := j - i

	// We find bytes including i and j, so we should sub j with 1.
	j -= 1
	if err := l.relocate(i); err != nil {
		return nil, err
	}

	// Linearly copy.

	if j < l.baseEnd {
		// In the same block, no copy needed.
		return l.baseData[i-l.baseStart : j-l.baseStart+1], nil
	}

	b := make([]byte, size)
	k := 0
	for j >= l.baseEnd {
		n := copy(b[k:], l.baseData[i-l.baseStart:])
		k += n
		i += n
		contiguous, err := l.advance()
		if err != nil {
			return nil, err
		}
		if !contiguous {
			return nil, ErrMissingCrypto
		}
	}
	copy(b[k:], l.baseData[i-l.baseStart:j-l.baseStart+1])
	return b, nil
}

func (l *LinearLocator) At(i int) (byte, error) {
	if len(l.o) == 0 {
		return 0, ErrMissingCrypto
	}

	if err := l.relocate(i); err != nil {
		return 0, err
	}
	b := l.baseData[i-l.baseStart]
	return b, nil
}

func (l *LinearLocator) Bytes() ([]byte, error) {
	return l.Range(0, l.length)
}

var _ Locator = &LinearLocator{}

func (l *LinearLocator) Len() int {
	return l.length
}

type BuiltinBytesLocator []byte

func (l BuiltinBytesLocator) Range(i, j int) ([]byte, error) {
	return l[i:j], nil
}
func (l BuiltinBytesLocator) At(i int) (byte, error) {
	return l[i], nil
}
func (l BuiltinBytesLocator) Len() int {
	return len(l)
}
func (l BuiltinBytesLocator) Bytes() ([]byte, error) {
	return l, nil
}

var _ Locator = BuiltinBytesLocator{}
