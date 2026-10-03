package control

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"math"
	"net"
	"sync"
	"time"

	"github.com/daeuniverse/dae/common"
	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/outbound/pkg/fastrand"
	"github.com/daeuniverse/outbound/pool"
	log "github.com/sirupsen/logrus"
)

const (
	dnsRetryInterval = 1 * time.Second
	dnsRetryCount    = 2

	// maxDnsIdRandomAttempts bounds the random draws used to find a free
	// transaction id before falling back to a deterministic linear probe.
	maxDnsIdRandomAttempts = 8

	// defaultDNSAttemptDeadline bounds a single DNS attempt's write
	// AND read against the upstream. Note: writing the underlying quic
	// stream could got stuck on not alive dialer's connection.
	defaultDNSAttemptDeadline = 2 * time.Second
)

type leveledError struct {
	err   error
	level log.Level
}

func (e *leveledError) Error() string {
	return e.err.Error()
}

func (e *leveledError) Unwrap() error {
	return e.err
}

func (e *leveledError) Level() log.Level {
	return e.level
}

// ErrDisabled is returned by AsXxx when the log level is disabled.
// It is used to trigger error handling without allocating a real error.
var ErrDisabled = errors.New("disabled")

var leveledErrorPool = sync.Pool{
	New: func() any {
		return &leveledError{}
	},
}

func getLeveledError(err error, level log.Level) error {
	if err == nil {
		return nil
	}
	le := leveledErrorPool.Get().(*leveledError)
	le.err = err
	le.level = level
	return le
}

func AsInfo(err error, format string, args ...any) error {
	if !log.IsLevelEnabled(log.InfoLevel) {
		return ErrDisabled
	}
	var wrappedErr error
	if err == nil {
		wrappedErr = common.Errf(format, args...)
	} else {
		wrappedErr = common.Wrap(err, format, args...)
	}
	return getLeveledError(wrappedErr, log.InfoLevel)
}
func AsWarn(err error, format string, args ...any) error {
	if !log.IsLevelEnabled(log.WarnLevel) {
		return ErrDisabled
	}
	var wrappedErr error
	if err == nil {
		wrappedErr = common.Errf(format, args...)
	} else {
		wrappedErr = common.Wrap(err, format, args...)
	}
	return getLeveledError(wrappedErr, log.WarnLevel)
}
func AsError(err error, format string, args ...any) error {
	if !log.IsLevelEnabled(log.ErrorLevel) {
		return ErrDisabled
	}
	var wrappedErr error
	if err == nil {
		wrappedErr = common.Errf(format, args...)
	} else {
		wrappedErr = common.Wrap(err, format, args...)
	}
	return getLeveledError(wrappedErr, log.ErrorLevel)
}
func AsDebug(err error, format string, args ...any) error {
	if !log.IsLevelEnabled(log.DebugLevel) {
		return ErrDisabled
	}
	var wrappedErr error
	if err == nil {
		wrappedErr = common.Errf(format, args...)
	} else {
		wrappedErr = common.Wrap(err, format, args...)
	}
	return getLeveledError(wrappedErr, log.DebugLevel)
}
func AsTrace(err error, format string, args ...any) error {
	if !log.IsLevelEnabled(log.TraceLevel) {
		return ErrDisabled
	}
	var wrappedErr error
	if err == nil {
		wrappedErr = common.Errf(format, args...)
	} else {
		wrappedErr = common.Wrap(err, format, args...)
	}
	return getLeveledError(wrappedErr, log.TraceLevel)
}

type DnsManager struct {
	conn    net.Conn
	mu      sync.Mutex
	recvMap map[uint16]chan []byte
	ctx     context.Context
	cancel  context.CancelFunc

	stream bool
	dialer string
}

func NewDnsManager(conn net.Conn, stream bool, dialer string) *DnsManager {
	ctx, cancel := context.WithCancel(context.TODO())
	m := &DnsManager{
		conn:    conn,
		recvMap: make(map[uint16]chan []byte),
		ctx:     ctx,
		cancel:  cancel,
		stream:  stream,
		dialer:  dialer,
	}
	go m.run()
	return m
}

func (m *DnsManager) run() {
	for {
		var data []byte
		var err error
		if data, err = m.read(); err != nil {
			if le, ok := err.(*leveledError); ok {
				if log.IsLevelEnabled(le.Level()) {
					log.WithError(err).Logf(le.Level(), "DnsManager closed, dialer: %v", m.dialer)
				}
				leveledErrorPool.Put(le)
			}
			m.Close()
			return
		}
		m.feed(data)
	}
}

func (m *DnsManager) read() (data []byte, err error) {
	if m.stream {
		var lenBuf [2]byte
		// Read two byte length.
		if _, err = io.ReadFull(m.conn, lenBuf[:]); err != nil {
			return nil, AsDebug(err, "failed to read tcp DNS resp payload length")
		}
		msgLen := int(binary.BigEndian.Uint16(lenBuf[:]))
		// Defensive bound: the two-byte length field cannot encode more than
		// consts.DnsMaxMessageSize, so this only trips if the framing changes.
		if msgLen > consts.DnsMaxMessageSize {
			return nil, AsWarn(err, "tcp dns msg len too large: %d > %d", msgLen, consts.DnsMaxMessageSize)
		}
		data = make([]byte, msgLen)
		if _, err = io.ReadFull(m.conn, data); err != nil {
			return nil, AsDebug(err, "failed to read tcp DNS resp payload")
		}
	} else {
		// MTU-sized on purpose: the upstream-facing query is clamped to
		// dnsUDPPayloadCap (1232) before it is sent, so a plain UDP upstream
		// can never legitimately answer with more than fits this bucket —
		// anything larger comes back over TCP via the TC bit instead. Keep
		// the two in sync: raising the clamp without raising this buffer
		// silently truncates answers again.
		buf := pool.GetBuffer(consts.EthernetMtu)
		var n int
		if n, err = m.conn.Read(buf); err != nil {
			pool.PutBuffer(buf)
			return nil, AsDebug(err, "failed to read udp DNS resp payload")
		}
		data = make([]byte, n)
		copy(data, buf[:n])
		pool.PutBuffer(buf)
	}
	return data, nil
}

func (m *DnsManager) feed(data []byte) {
	if len(data) < 12 {
		log.Errorf("Wrong DNS response: length %d too short, data: %v", len(data), data)
		return
	}
	id := dnsId(data)
	// The lookup AND the delivery must happen under m.mu. Resolve removes its
	// entry, drains the channel and returns it to recvChannelPool under the
	// same lock; if the send were done after unlocking, a response arriving in
	// that window would be pushed into a recycled channel and then handed to an
	// unrelated Resolve call, which would return this foreign response (for a
	// different question) as its own answer.
	m.mu.Lock()
	ch, ok := m.recvMap[id]
	if !ok {
		m.mu.Unlock()
		if log.IsLevelEnabled(log.DebugLevel) {
			log.Debugf("Unknown dns resp msg, stream: %v, id: %v", m.stream, id)
		}
		// Ignore message from unknown session
		return
	}

	select {
	case ch <- data:
		// OK
	default:
		if log.IsLevelEnabled(log.DebugLevel) {
			log.Debugf("Drop dns resp msg, stream: %v, id: %v", m.stream, id)
		}
		// Channel full, drop the message
	}
	m.mu.Unlock()
}

func (m *DnsManager) Close() error {
	m.cancel()
	return m.conn.Close()
}

func (m *DnsManager) IsClosed() bool {
	return m.ctx.Err() != nil
}

func writeData(conn net.Conn, data []byte, isStream bool) error {
	if isStream {
		var head [2]byte
		binary.BigEndian.PutUint16(head[:], uint16(len(data)))
		v := net.Buffers{head[:], data}
		_, err := v.WriteTo(conn)
		return err
	} else {
		_, err := conn.Write(data)
		return err
	}
}

var recvChannelPool = sync.Pool{
	New: func() any {
		return make(chan []byte, 1)
	},
}

var resolveTimerPool = sync.Pool{
	New: func() any {
		timer := time.NewTimer(time.Hour)
		timer.Stop()
		return timer
	},
}

// claimDnsIdLocked returns a transaction id that is not currently registered
// in recvMap. It must be called with m.mu held. A few random draws find a free
// slot immediately in practice (recvMap holds only in-flight queries); the
// linear probe guarantees termination even under pathological density.
func claimDnsIdLocked(recvMap map[uint16]chan []byte) uint16 {
	for range maxDnsIdRandomAttempts {
		id := uint16(fastrand.Intn(math.MaxUint16))
		if _, dup := recvMap[id]; !dup {
			return id
		}
	}
	for id := 0; id <= math.MaxUint16; id++ {
		if _, dup := recvMap[uint16(id)]; !dup {
			return uint16(id)
		}
	}
	// recvMap is full (65536 in-flight queries on one manager); fall back to a
	// random id rather than deadlocking.
	return uint16(fastrand.Intn(math.MaxUint16))
}

func (m *DnsManager) Resolve(ctx context.Context, data []byte) ([]byte, error) {
	origMsgId := dnsId(data)

	recvCh := recvChannelPool.Get().(chan []byte)
	m.mu.Lock()
	// recvMap keys the demultiplexer, so a duplicate id silently steals the
	// other in-flight query's channel: both responses for that id are then
	// delivered to whichever query registered last. That is how a client can
	// receive a well-formed answer to a *different* question (e.g. an A answer
	// in reply to its AAAA query). Claim a free id instead of overwriting.
	newId := claimDnsIdLocked(m.recvMap)
	m.recvMap[newId] = recvCh
	m.mu.Unlock()

	// Only stamp the claimed id onto the wire buffer after it is owned, so a
	// concurrent Resolve on a shared buffer never sees a half-claimed id.
	dnsIdSet(data, newId)

	var timer *time.Timer
	defer func() {
		// Cleanup timer
		if timer != nil {
			if !timer.Stop() {
				select {
				case <-timer.C:
				default:
				}
			}
			resolveTimerPool.Put(timer)
		}
		m.mu.Lock()
		delete(m.recvMap, newId)
		m.mu.Unlock()
		// Cleanup recvCh
		select {
		case <-recvCh:
		default:
		}
		recvChannelPool.Put(recvCh)
		dnsIdSet(data, origMsgId)
	}()

	for range dnsRetryCount {
		m.conn.SetWriteDeadline(time.Now().Add(defaultDNSAttemptDeadline))
		if err := writeData(m.conn, data, m.stream); err != nil {
			return nil, err
		}
		m.conn.SetReadDeadline(time.Now().Add(defaultDNSAttemptDeadline))
		if timer == nil {
			timer = resolveTimerPool.Get().(*time.Timer)
		}
		timer.Reset(dnsRetryInterval)

		select {
		case <-m.ctx.Done():
			return nil, net.ErrClosed
		case <-ctx.Done():
			return nil, context.Canceled
		case recvMsg := <-recvCh:
			return recvMsg, nil
		case <-timer.C:
		}
	}

	if log.IsLevelEnabled(log.WarnLevel) {
		qInfo := dnsQueryInfo(data)
		log.Warnf("dns timeout, stream: %v, qname: %v, qtype: %v", m.stream, qInfo.qname, qInfo.qtype)
	}
	return nil, context.DeadlineExceeded
}
