/*
*  SPDX-License-Identifier: AGPL-3.0-only
*  Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package dialer

import (
	"context"
	"fmt"
	"io"
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

// underlyingRefs counts Dialer wrappers that share one underlying
// netproxy.Dialer. Clones (created for group-level option overrides) wrap the
// SAME underlying dialer as the original: Disconnecting the shared pool when
// only one wrapper is being closed would kill every connection other groups
// still hold through that node. The underlying is disconnected only when the
// last wrapper closes. Construction and Close are rare (init / update-sub),
// so a plain mutex is fine.
var (
	underlyingRefsMu sync.Mutex
	underlyingRefs   = make(map[netproxy.Dialer]int)
)

func refUnderlying(u netproxy.Dialer) {
	underlyingRefsMu.Lock()
	underlyingRefs[u]++
	underlyingRefsMu.Unlock()
}

// unrefUnderlying reports whether the caller holds the last reference and
// must disconnect the underlying dialer.
func unrefUnderlying(u netproxy.Dialer) bool {
	underlyingRefsMu.Lock()
	defer underlyingRefsMu.Unlock()
	underlyingRefs[u]--
	if underlyingRefs[u] <= 0 {
		delete(underlyingRefs, u)
		return true
	}
	return false
}

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

	// udpEndpoints holds every live UDP endpoint (UdpEndpoint) created
	// through this dialer. AbortConns closes them alongside the TCP pairs:
	// UDP endpoints are NOT covered by activeConns, so without this a
	// dialer flipping alive -> not alive used to leave QUIC/HTTP-3 flows
	// blackholing on a dead anytls session until their own NAT timeout.
	udpEndpoints   map[io.Closer]struct{}
	udpEndpointsMu sync.Mutex

	// abortConnsTimer is armed when the dialer transitions alive -> not
	// alive and fires AbortConns one CheckInterval later unless a recovery
	// disarms it first: two consecutive failed check rounds are treated as
	// a real death, a single flapped round is not. Guarded by mu.
	abortConnsTimer *time.Timer
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
		udpEndpoints:           make(map[io.Closer]struct{}),
		tickerMu:               sync.Mutex{},
		ticker:                 nil,
		checkCh:                make(chan time.Time, 1),
		checkCtx:               checkCtx,
		checkCancel:            checkCancel,
	}
	d.alive.Store(!needAliveState)
	refUnderlying(dialer)
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
	d.cancelAbortConns()
	// AbortConns first: this dialer is going away (e.g. dialer removed from
	// config via update-sub, or the daemon is shutting down), so every
	// relay using it must exit.
	d.AbortConns()
	// Per-wrapper teardown is done; the underlying pool goes away only with
	// the LAST wrapper. Clones share one underlying dialer: closing a
	// discarded clone must not Disconnect the shared pool out from under
	// groups that still reference the node.
	if !unrefUnderlying(d.Dialer) {
		return nil
	}
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
	d.AbortUdpEndpoints()
}

// RegisterUdpEndpoint registers a live UDP endpoint created through this
// dialer so that AbortConns (alive -> not alive, or dialer removal) can
// close it. The returned unregister func removes the entry; call it when
// the endpoint is closed for any other reason. Closing an already-closed
// endpoint from AbortConns is safe (idempotent), so a stale entry that
// raced with a natural close is harmless.
func (d *Dialer) RegisterUdpEndpoint(ue io.Closer) (unregister func()) {
	d.udpEndpointsMu.Lock()
	defer d.udpEndpointsMu.Unlock()
	d.udpEndpoints[ue] = struct{}{}
	return func() {
		d.udpEndpointsMu.Lock()
		defer d.udpEndpointsMu.Unlock()
		delete(d.udpEndpoints, ue)
	}
}

// AbortUdpEndpoints closes every registered UDP endpoint and empties the
// registry. Safe to call with activeConnsMu held (AbortConns does):
// endpoint Close paths never take activeConnsMu, so no lock cycle exists.
func (d *Dialer) AbortUdpEndpoints() {
	d.udpEndpointsMu.Lock()
	defer d.udpEndpointsMu.Unlock()
	for ue := range d.udpEndpoints {
		ue.Close()
	}
	clear(d.udpEndpoints)
}
