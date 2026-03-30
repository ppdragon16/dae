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
)

type LeveledError interface {
	error
	Level() log.Level
}

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
	recvMap sync.Map // map[uint32]chan *dnsmessage.Msg
	ctx     context.Context
	cancel  context.CancelFunc

	stream bool
	dialer string
}

func NewDnsManager(conn net.Conn, stream bool, dialer string) *DnsManager {
	ctx, cancel := context.WithCancel(context.TODO())
	m := &DnsManager{
		conn:   conn,
		ctx:    ctx,
		cancel: cancel,
		stream: stream,
		dialer: dialer,
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
		if msgLen > consts.EthernetMtu {
			return nil, AsWarn(err, "tcp dns msg len too large: %d > %d", msgLen, consts.EthernetMtu)
		}
		data = make([]byte, msgLen)
		if _, err = io.ReadFull(m.conn, data); err != nil {
			return nil, AsDebug(err, "failed to read tcp DNS resp payload")
		}
	} else {
		data = make([]byte, consts.EthernetMtu)
		var n int
		if n, err = m.conn.Read(data); err != nil {
			return nil, AsDebug(err, "failed to read udp DNS resp payload")
		}
		data = data[:n]
	}
	return data, nil
}

func (m *DnsManager) feed(data []byte) {
	if len(data) < 12 {
		log.Errorf("Wrong DNS response: length %d too short, data: %v", len(data), data)
		return
	}
	id := dnsId(data)
	conn, ok := m.recvMap.Load(id)
	if !ok {
		if log.IsLevelEnabled(log.DebugLevel) {
			log.Debugf("Unknown dns resp msg, stream: %v, id: %v", m.stream, id)
		}
		// Ignore message from unknown session
		return
	}

	select {
	case conn.(chan []byte) <- data:
		// OK
	default:
		if log.IsLevelEnabled(log.DebugLevel) {
			log.Debugf("Drop dns resp msg, stream: %v, id: %v", m.stream, id)
		}
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

func (m *DnsManager) Resolve(ctx context.Context, data []byte) ([]byte, error) {
	origMsgId := dnsId(data)
	newId := uint16(fastrand.Intn(math.MaxUint16))
	dnsIdSet(data, newId)
	defer func() { dnsIdSet(data, origMsgId) }()
	dataToWrite := data
	if m.stream {
		dataToWrite = pool.GetBuffer(len(data) + 2)
		defer pool.PutBuffer(dataToWrite)
		binary.BigEndian.PutUint16(dataToWrite, uint16(len(data)))
		copy(dataToWrite[2:], data)
	}

	recvCh := make(chan []byte, 1)
	m.recvMap.Store(newId, recvCh)
	defer m.recvMap.Delete(newId)

	timer := time.NewTimer(dnsRetryInterval)
	defer timer.Stop()

	for i := range dnsRetryCount {
		if _, err := m.conn.Write(dataToWrite); err != nil {
			return nil, err
		}
		if i > 0 {
			timer.Reset(dnsRetryInterval)
		}
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

	qInfo := dnsQueryInfo(data)
	log.Warnf("dns timeout, stream: %v, qname: %v, qtype: %v", m.stream, qInfo.qname, qInfo.qtype)
	return nil, context.DeadlineExceeded
}
