/*
*  SPDX-License-Identifier: AGPL-3.0-only
*  Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package dialer

import (
	"context"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"
	"unsafe"

	"github.com/daeuniverse/dae/config"
	D "github.com/daeuniverse/outbound/dialer"
	"github.com/daeuniverse/outbound/netproxy"
	log "github.com/sirupsen/logrus"
)

var (
	UnexpectedFieldErr  = fmt.Errorf("unexpected field")
	InvalidParameterErr = fmt.Errorf("invalid parameters")
)

type DialerGroup interface {
	NotifyStatusChange(*Dialer)
	GetEmaAlpha() float64
	GetTimeoutPenalty() time.Duration
}

type Dialer struct {
	*GlobalOption
	netproxy.Dialer
	*Property

	needAliveState bool
	alive          atomic.Bool
	supported      atomic.Uint32
	// noIpv6 is set by the initial connectivity check and marks a dialer
	// that cannot proxy IPv6 traffic (neither tcp6 nor udp6 supported).
	// DNS AAAA requests are rejected before being forwarded through it.
	noIpv6        atomic.Bool
	Latencies10   map[DialerGroup]*LatenciesN
	MovingAverage map[DialerGroup]time.Duration

	mu                     sync.Mutex
	registeredDialerGroups map[DialerGroup]int

	tickerMu    sync.Mutex
	ticker      *time.Ticker
	checkCh     chan time.Time
	checkCtx    context.Context
	checkCancel context.CancelFunc

	checkActivated bool

	// activeConns maps rConn -> lConn for every connection pair created
	// by this dialer. AbortConns uses this to close BOTH ends of the relay
	// when the dialer transitions alive -> not alive, so a relay goroutine
	// stuck in Write(lConn) or Read(lConn) actually gets unblocked.
	// Every access happens under activeConnsMu, so a plain map suffices;
	// sync.Map would only add per-entry allocation overhead (HashTrieMap
	// nodes) with no lock-free reader to justify it.
	activeConns   map[net.Conn]net.Conn
	activeConnsMu sync.Mutex
}
type GlobalOption struct {
	D.ExtraOption
	// TcpCheckOptionRaw TcpCheckOptionRaw // Lazy parse
	CheckDnsOptionRaw CheckDnsOptionRaw // Lazy parse
	CheckInterval     time.Duration
	CheckTolerance    time.Duration
	CheckDnsTcp       bool
}

type Property struct {
	D.Property
	SubscriptionTag string
}

func NewGlobalOption(global *config.GlobalTrimmed) *GlobalOption {
	return &GlobalOption{
		ExtraOption: D.ExtraOption{
			AllowInsecure:       global.AllowInsecure,
			TlsImplementation:   global.TlsImplementation,
			UtlsImitate:         global.UtlsImitate,
			BandwidthMaxTx:      global.BandwidthMaxTx,
			BandwidthMaxRx:      global.BandwidthMaxRx,
			TlsFragment:         global.TlsFragment,
			TlsFragmentLength:   global.TlsFragmentLength,
			TlsFragmentInterval: global.TlsFragmentInterval,
			UDPHopInterval:      global.UDPHopInterval,
		},
		// TcpCheckOptionRaw: TcpCheckOptionRaw{Raw: global.TcpCheckUrl, Method: global.TcpCheckHttpMethod},
		CheckDnsOptionRaw: CheckDnsOptionRaw{Raw: global.UdpCheckDns},
		CheckInterval:     global.CheckInterval,
		CheckTolerance:    global.CheckTolerance,
		CheckDnsTcp:       true,
	}
}

// NewDialer is for register in general.
func NewDialer(dialer netproxy.Dialer, option *GlobalOption, property *Property, needAliveState bool) *Dialer {
	checkCtx, checkCancel := context.WithCancel(context.Background())
	d := &Dialer{
		GlobalOption:           option,
		Dialer:                 dialer,
		Property:               property,
		needAliveState:         needAliveState,
		Latencies10:            make(map[DialerGroup]*LatenciesN),
		MovingAverage:          make(map[DialerGroup]time.Duration),
		registeredDialerGroups: make(map[DialerGroup]int),
		activeConns:            make(map[net.Conn]net.Conn),
		tickerMu:               sync.Mutex{},
		ticker:                 nil,
		checkCh:                make(chan time.Time, 1),
		checkCtx:               checkCtx,
		checkCancel:            checkCancel,
	}
	d.alive.Store(!needAliveState)
	log.WithField("dialer", d.Name).
		WithField("p", unsafe.Pointer(d)).
		Traceln("NewDialer")
	return d
}

func (d *Dialer) NeedAliveState() bool {
	return d.needAliveState
}

// NoIpv6 reports whether this dialer is known to be unable to proxy IPv6
// traffic, as determined by the initial connectivity check.
func (d *Dialer) NoIpv6() bool {
	return d.noIpv6.Load()
}

func (d *Dialer) Clone() *Dialer {
	return NewDialer(d.Dialer, d.GlobalOption, d.Property, d.needAliveState)
}

func (d *Dialer) stopCheck() {
	d.checkCancel()
	d.tickerMu.Lock()
	if d.ticker != nil {
		d.ticker.Stop()
		d.ticker = nil
	}
	d.tickerMu.Unlock()
}

func (d *Dialer) Close() error {
	d.stopCheck()
	// AbortConns first: this dialer is going away (e.g. dialer removed from
	// config via update-sub, or the daemon is shutting down), so every
	// relay using it must exit.
	d.AbortConns()
	return d.Dialer.Disconnect()
}

// RegisterConn registers a connection created by this dialer. lConn is the
// local-side conn that the relay in control/tcp.go will use to push data to
// the client; rConn is the upstream-side conn returned by DialContext. We
// keep the lConn alongside the rConn so AbortConns can close BOTH sides of
// the relay, which is required to break out of a relay goroutine stuck in a
// blocking Write(lConn) or Read(lConn) that rConn close alone cannot reach
// (and which would otherwise leave dae_active_connections pinned for the
// duration of DefaultTCPIdleTimeout, or until the client happens to close).
func (d *Dialer) RegisterConn(lConn, rConn net.Conn) {
	d.activeConnsMu.Lock()
	defer d.activeConnsMu.Unlock()
	d.activeConns[rConn] = lConn
}

// UnregisterConn unregisters a connection from this dialer.
func (d *Dialer) UnregisterConn(rConn net.Conn) {
	d.activeConnsMu.Lock()
	defer d.activeConnsMu.Unlock()
	delete(d.activeConns, rConn)
}

// AbortConns closes every registered connection pair (lConn + rConn) and
// empties the registry. Closing lConn FIRST is important: if a relay
// goroutine is stuck in Write(lConn) (because the client stopped reading
// and the local kernel send buffer is full), the rConn close from
// QStream.CancelRead/Close only unblocks reads on rConn — it does NOT
// unblock the Write(lConn) call. Closing lConn forces the Write to return
// with a "use of closed network connection" error, which is the only thing
// that lets the relay goroutine actually exit and run its defers
// (activeConnectionsCounter.Dec, UnregisterConn, rLogConn.Close).
func (d *Dialer) AbortConns() {
	d.activeConnsMu.Lock()
	defer d.activeConnsMu.Unlock()
	for rConn, lConn := range d.activeConns {
		// Close the local side first so a goroutine parked in
		// Write(lConn) or Read(lConn) gets unblocked; then close
		// the upstream side to also unblock the opposite relay
		// direction.
		if lConn != nil {
			lConn.Close()
		}
		rConn.Close()
	}
	clear(d.activeConns)
}
