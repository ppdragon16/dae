/*
*  SPDX-License-Identifier: AGPL-3.0-only
*  Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"context"
	"encoding/binary"
	"errors"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"

	log "github.com/sirupsen/logrus"

	"github.com/daeuniverse/dae/component/outbound/dialer"
	"github.com/daeuniverse/outbound/pool"
)

// mmsghdr mirrors Linux struct mmsghdr for sendmmsg(2).
// Not defined in x/sys/unix, so we define it here.
type mmsghdr struct {
	hdr    unix.Msghdr
	msgLen uint32
	_      [4]byte // pad to 64 bytes; kernel strides at 64 B
}

const (
	sendBufSlots   = 16
	sendBufTimeout = 10 * time.Millisecond

	// batchThreshold is the number of direct writes before the
	// connection switches permanently from direct sendto to batched
	// sendmmsg.  Below this threshold, writes go directly to avoid
	// the timer latency for sparse traffic like H3 page loads.
	batchThreshold = sendBufSlots / 2 // 8
)

type sendReq struct {
	data []byte // pool buffer, freed after flush
	dst  netip.AddrPort
}

type sendBuf struct {
	mu    sync.Mutex
	reqs  [sendBufSlots]sendReq
	count int
	timer *time.Timer // fires sendBufTimeout after first request
}

type Anyfrom struct {
	*net.UDPConn
	deadlineTimer *time.Timer
	ttl           time.Duration
	refCount      int32

	// fd is the cached raw file descriptor, obtained once from
	// SyscallConn().  Used by BatchWriteToAddrPort to bypass the
	// Go net layer.
	fd int // 0 = not resolved; real UDP fds are always > 0

	sBuf sendBuf

	// Burst detection: writes are counted in a sliding sendBufTimeout
	// window.  Below batchThreshold they go direct; above it they switch
	// to batched sendmmsg.  When the gap since the last write exceeds
	// sendBufTimeout the counter resets.  Pending batch data is always
	// flushed by the timer, so no lock is needed here.
	singleWriteCount atomic.Int64
	lastWriteNano    atomic.Int64
}

// AnyfromPool is a full-cone udp listener pool
type AnyfromPool struct {
	pool    map[netip.AddrPort]*Anyfrom
	mu      sync.RWMutex
	afReqCh chan *afRequest
}

var DefaultAnyfromPool *AnyfromPool = nil

func NewAnyfromPool() *AnyfromPool {
	return &AnyfromPool{
		pool:    make(map[netip.AddrPort]*Anyfrom, 64),
		afReqCh: make(chan *afRequest, 128),
	}
}

type afResponse struct {
	conn *net.UDPConn
	err  error
}

type afRequest struct {
	lAddr   string
	afResCh chan *afResponse
}

func (p *AnyfromPool) Start(ctx context.Context) {
	lc := net.ListenConfig{
		Control: func(network string, address string, c syscall.RawConn) error {
			return dialer.TransparentControl(c)
		},
		KeepAlive: 0,
	}
	GetDaeNetns().With(func() error {
		defer func() {
			p.mu.Lock()
			defer p.mu.Unlock()
			for _, af := range p.pool {
				if af.deadlineTimer != nil {
					af.deadlineTimer.Stop()
				}
				af.Close()
			}
			p.pool = make(map[netip.AddrPort]*Anyfrom)
		}()
		for {
			select {
			case <-ctx.Done():
				return nil
			case req, ok := <-p.afReqCh:
				if !ok {
					return nil
				}
				pc, err := lc.ListenPacket(ctx, "udp", req.lAddr)
				if err != nil {
					req.afResCh <- &afResponse{conn: nil, err: err}
				} else {
					req.afResCh <- &afResponse{conn: pc.(*net.UDPConn), err: nil}
				}
			}
		}
	})
}

func (p *AnyfromPool) createAnyfrom(lAddr netip.AddrPort, ttl time.Duration) (*Anyfrom, error) {
	afResCh := make(chan *afResponse, 1)
	p.afReqCh <- &afRequest{lAddr: lAddr.String(), afResCh: afResCh}
	select {
	case afRes := <-afResCh:
		if afRes.err != nil {
			return nil, afRes.err
		}

		initialRefCount := int32(1)
		if ttl == 0 {
			// zero-ttl means "immortal".
			initialRefCount = 2
		}
		af := &Anyfrom{
			UDPConn:  afRes.conn,
			ttl:      ttl,
			refCount: initialRefCount,
		}

		p.pool[lAddr] = af
		return af, nil
	case <-time.After(1 * time.Second):
		return nil, errors.New("timeout to create UDP conn for Anyfrom")
	}
}

func (p *AnyfromPool) Obtain(lAddr netip.AddrPort, ttl time.Duration) (conn *Anyfrom, err error) {
	p.mu.RLock()
	af, ok := p.pool[lAddr]
	if ok {
		atomic.AddInt32(&af.refCount, 1)
		p.mu.RUnlock()
		return af, nil
	}
	p.mu.RUnlock()

	p.mu.Lock()
	defer p.mu.Unlock()

	if af, ok = p.pool[lAddr]; ok {
		atomic.AddInt32(&af.refCount, 1)
		return af, nil
	}

	return p.createAnyfrom(lAddr, ttl)
}

// ensureFD lazily resolves the raw file descriptor from SyscallConn.
func (af *Anyfrom) ensureFD() error {
	if af.fd != 0 {
		return nil
	}
	rawConn, err := af.SyscallConn()
	if err != nil {
		return err
	}
	return rawConn.Control(func(fd uintptr) {
		af.fd = int(fd)
	})
}

// BatchWriteToAddrPort buffers b and sends it to dst after at most
// sendBufTimeout.  Batching 8 requests reduces syscall count while
// keeping worst-case latency bounded to 10 ms.
func (af *Anyfrom) BatchWriteToAddrPort(b []byte, dst netip.AddrPort) (int, error) {
	if err := af.ensureFD(); err != nil {
		return 0, err
	}

	// Copy data — the caller reuses b after we return.
	data := pool.GetBuffer(len(b))
	copy(data, b)

	af.sBuf.mu.Lock()

	idx := af.sBuf.count
	// If same destination as previous slot, zero the dst so
	// flushLocked can reuse the previous sockaddr encoding.
	if idx > 0 && af.sBuf.reqs[idx-1].dst == dst {
		af.sBuf.reqs[idx] = sendReq{data: data}
	} else {
		af.sBuf.reqs[idx] = sendReq{data: data, dst: dst}
	}
	af.sBuf.count++

	if af.sBuf.count == 1 {
		// First request in the batch: arm the flush timer.
		if af.sBuf.timer == nil {
			af.sBuf.timer = time.AfterFunc(sendBufTimeout, af.flushSendBuf)
		} else {
			af.sBuf.timer.Reset(sendBufTimeout)
		}
	} else if af.sBuf.count >= sendBufSlots {
		// Buffer full — stop the timer and flush now.
		if af.sBuf.timer != nil {
			af.sBuf.timer.Reset(time.Hour) // effectively stop the timer
		}
		af.flushLocked()
	}

	af.sBuf.mu.Unlock()
	return len(b), nil
}

// WriteToAddrPort writes b to dst, choosing between direct sendto and
// batched sendmmsg automatically.  Writes are counted in a sliding
// sendBufTimeout window.  Below batchThreshold they go direct; above
// it they go batched for the remainder of the window.  When the gap
// since the last write exceeds sendBufTimeout the counter resets,
// preventing low-frequency flows (e.g. DoQ) from entering batch mode.
// Pending batch data is flushed by the timer — no explicit flush is
// needed on window expiry.
// Callers that must bypass batching (e.g. DNS, games) can use the
// promoted WriteToUDPAddrPort directly.
func (af *Anyfrom) WriteToAddrPort(b []byte, dst netip.AddrPort) (int, error) {
	now := time.Now().UnixNano()
	if now-af.lastWriteNano.Load() > sendBufTimeout.Nanoseconds() {
		af.singleWriteCount.Store(0)
	}
	af.lastWriteNano.Store(now)

	if af.singleWriteCount.Add(1) <= batchThreshold {
		// Flush any pending batch data from a previous window to
		// preserve packet ordering.  Normally the timer has already
		// fired, but scheduling delays can leave data stranded.
		af.flushSendBuf()
		return af.UDPConn.WriteToUDPAddrPort(b, dst)
	}
	return af.BatchWriteToAddrPort(b, dst)
}

// flushSendBuf is the timer callback; it runs in its own goroutine.
func (af *Anyfrom) flushSendBuf() {
	af.sBuf.mu.Lock()
	af.flushLocked()
	af.sBuf.mu.Unlock()
}

// flushLocked drains the batch via sendmmsg(2).  Must hold af.sBuf.mu.
func (af *Anyfrom) flushLocked() {
	n := af.sBuf.count
	if n == 0 {
		return
	}

	var msgs [sendBufSlots]mmsghdr
	var iovs [sendBufSlots]unix.Iovec
	var rawAddrs [sendBufSlots][28]byte
	var addrLens [sendBufSlots]uint32

	lastValid := 0
	for i := range n {
		req := &af.sBuf.reqs[i]

		iovs[i] = unix.Iovec{Base: &req.data[0], Len: uint64(len(req.data))}

		if req.dst.IsValid() {
			// Encode sockaddr for this slot.
			addr := req.dst.Addr()
			port := req.dst.Port()
			if addr.Is4() {
				rawAddrs[i][0], rawAddrs[i][1] = 2, 0
				binary.BigEndian.PutUint16(rawAddrs[i][2:4], port)
				a4 := addr.As4()
				copy(rawAddrs[i][4:8], a4[:])
				addrLens[i] = 16
			} else {
				rawAddrs[i][0], rawAddrs[i][1] = 10, 0
				binary.BigEndian.PutUint16(rawAddrs[i][2:4], port)
				a16 := addr.As16()
				copy(rawAddrs[i][8:24], a16[:])
				addrLens[i] = 28
			}
			lastValid = i
			msgs[i] = mmsghdr{
				hdr: unix.Msghdr{
					Name:    &rawAddrs[i][0],
					Namelen: addrLens[i],
					Iov:     &iovs[i],
					Iovlen:  1,
				},
			}
		} else {
			// Same destination as a previous slot; reuse its sockaddr.
			msgs[i] = mmsghdr{
				hdr: unix.Msghdr{
					Name:    &rawAddrs[lastValid][0],
					Namelen: addrLens[lastValid],
					Iov:     &iovs[i],
					Iovlen:  1,
				},
			}
		}
	}

	_, _, e := unix.Syscall6(
		unix.SYS_SENDMMSG,
		uintptr(af.fd),
		uintptr(unsafe.Pointer(&msgs[0])),
		uintptr(n),
		0, 0, 0,
	)
	if e != 0 {
		log.Debugf("[sendmmsg] flush error: %v", e)
	}

	// Free data buffers.
	for i := range n {
		pool.PutBuffer(af.sBuf.reqs[i].data)
		af.sBuf.reqs[i].data = nil
	}
	af.sBuf.count = 0
}

func (af *Anyfrom) Close() error {
	if af.sBuf.timer != nil {
		af.sBuf.timer.Stop()
		af.sBuf.timer = nil
	}
	if af.deadlineTimer != nil {
		af.deadlineTimer.Stop()
		af.deadlineTimer = nil
	}
	return af.UDPConn.Close()
}

func (p *AnyfromPool) Recycle(lAddr netip.AddrPort, af *Anyfrom) {
	if atomic.AddInt32(&af.refCount, -1) > 0 {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if af.deadlineTimer != nil {
		af.deadlineTimer.Reset(af.ttl)
	} else {
		af.deadlineTimer = time.AfterFunc(af.ttl, func() {
			if atomic.LoadInt32(&af.refCount) > 0 {
				return
			}
			p.mu.Lock()
			defer p.mu.Unlock()
			if atomic.LoadInt32(&af.refCount) <= 0 {
				if p.pool[lAddr] == af {
					delete(p.pool, lAddr)
				}
				af.Close()
			}
		})
	}
}
