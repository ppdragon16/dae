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
	dnsmessage "github.com/miekg/dns"
	log "github.com/sirupsen/logrus"
)

const (
	dnsRetryInterval = 1 * time.Second
	dnsRetryCount    = 2

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
	recvMap map[uint16]chan *dnsmessage.Msg
	ctx     context.Context
	cancel  context.CancelFunc

	stream bool
	dialer string
}

func NewDnsManager(conn net.Conn, stream bool, dialer string) *DnsManager {
	ctx, cancel := context.WithCancel(context.TODO())
	m := &DnsManager{
		conn:    conn,
		recvMap: make(map[uint16]chan *dnsmessage.Msg),
		ctx:     ctx,
		cancel:  cancel,
		stream:  stream,
		dialer:  dialer,
	}
	go m.run()
	return m
}

func (m *DnsManager) run() {
	buf := pool.GetBuffer(consts.EthernetMtu)
	defer pool.PutBuffer(buf)
	for {
		var data []byte
		var err error
		if data, err = m.read(buf); err != nil {
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

func (m *DnsManager) read(buf []byte) (data []byte, err error) {
	if m.stream {
		msgLenBuf := buf[:2]
		// Read two byte length.
		if _, err = io.ReadFull(m.conn, msgLenBuf); err != nil {
			return data, AsDebug(err, "failed to read tcp DNS resp payload length")
		}
		msgLen := int(binary.BigEndian.Uint16(msgLenBuf))
		if msgLen > len(buf) {
			return data, AsWarn(err, "tcp dns msg len too large: %d > %d", msgLen, len(buf))
		}
		data = buf[:msgLen]
		if _, err = io.ReadFull(m.conn, data); err != nil {
			return data, AsDebug(err, "failed to read tcp DNS resp payload")
		}
	} else {
		var n int
		if n, err = m.conn.Read(buf); err != nil {
			return data, AsDebug(err, "failed to read udp DNS resp payload")
		}
		data = buf[:n]
	}
	return data, nil
}

func (m *DnsManager) feed(data []byte) {
	var msg dnsmessage.Msg
	err := msg.Unpack(data)
	if err != nil {
		log.Warnf("Failed to unpack dns resp, stream: %v, err: %v, data: %v", m.stream, err, data)
		return
	}
	m.mu.Lock()
	ch, ok := m.recvMap[msg.Id]
	m.mu.Unlock()
	if !ok {
		log.Debugf("Unknown dns resp msg, stream: %v, id: %v", m.stream, msg.Id)
		// Ignore message from unknown session
		return
	}

	select {
	case ch <- &msg:
		// OK
	default:
		log.Debugf("Drop dns resp msg, stream: %v, id: %v", m.stream, msg.Id)
		// Channel full, drop the message
	}
}

func (m *DnsManager) Close() error {
	m.cancel()
	return m.conn.Close()
}

func (m *DnsManager) IsClosed() bool {
	return m.ctx.Err() != nil
}

var recvChannelPool = sync.Pool{
	New: func() any {
		return make(chan *dnsmessage.Msg, 1)
	},
}

var resolveTimerPool = sync.Pool{
	New: func() any {
		timer := time.NewTimer(time.Hour)
		timer.Stop()
		return timer
	},
}

func (m *DnsManager) Resolve(ctx context.Context, msg *dnsmessage.Msg) error {
	origMsgId := msg.Id
	msg.Id = uint16(fastrand.Intn(math.MaxUint16))
	defer func() { msg.Id = origMsgId }()
	buf := pool.GetBuffer(1024)
	defer pool.PutBuffer(buf)
	var data []byte
	var err error
	if m.stream {
		if data, err = msg.PackBuffer(buf[2:]); err == nil {
			dataLen := uint16(len(data))
			binary.BigEndian.PutUint16(buf, dataLen)
			data = buf[:dataLen+2]
		}
	} else {
		data, err = msg.PackBuffer(buf)
	}
	if err != nil {
		return common.Wrap(err, "pack DNS packet")
	}

	recvCh := recvChannelPool.Get().(chan *dnsmessage.Msg)
	m.mu.Lock()
	m.recvMap[msg.Id] = recvCh
	m.mu.Unlock()

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
		delete(m.recvMap, msg.Id)
		m.mu.Unlock()
		// Cleanup recvCh
		select {
		case <-recvCh:
		default:
		}
		recvChannelPool.Put(recvCh)
	}()

	for range dnsRetryCount {
		m.conn.SetWriteDeadline(time.Now().Add(defaultDNSAttemptDeadline))
		if _, err := m.conn.Write(data); err != nil {
			return err
		}
		m.conn.SetReadDeadline(time.Now().Add(defaultDNSAttemptDeadline))
		if timer == nil {
			timer = resolveTimerPool.Get().(*time.Timer)
		}
		timer.Reset(dnsRetryInterval)

		select {
		case <-m.ctx.Done():
			return net.ErrClosed
		case <-ctx.Done():
			return context.Canceled
		case recvMsg := <-recvCh:
			*msg = *recvMsg
			return nil
		case <-timer.C:
		}
	}

	var qname string
	var qtype uint16
	if len(msg.Question) > 0 {
		qname = msg.Question[0].Name
		qtype = msg.Question[0].Qtype
	}
	log.Warnf("dns timeout, stream: %v, qname: %v, qtype: %v", m.stream, qname, qtype)
	return context.DeadlineExceeded
}
