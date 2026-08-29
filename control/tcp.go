/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"math"
	"net"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/daeuniverse/dae/common"
	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/component/sniffing"
	"github.com/daeuniverse/outbound/netproxy"
	"github.com/daeuniverse/outbound/pkg/fastrand"
	"github.com/daeuniverse/outbound/pool"
	dnsmessage "github.com/miekg/dns"
	log "github.com/sirupsen/logrus"
)

const (
	// DefaultTCPIdleTimeout bounds the Read deadline: if neither side
	// produces data for this long, the relay considers the connection
	// idle and tears it down. 60 min is conservative — it must be
	// long enough to never trip on legitimate long-lived sockets
	// (push-notification keep-alives, video streams, etc.).
	DefaultTCPIdleTimeout = 60 * time.Minute

	// DefaultTCPWriteTimeout bounds the Write deadline: if a single
	// dst.Write call doesn't return within this window, the relay
	// gives up on the connection. Unlike Read, this is about
	// FAILURE DETECTION, not idle cleanup. The motivation is the
	// g2 (upload) direction, where dst.Write targets a hy2 QUIC
	// stream: when the upstream link dies, quic-go's framer can sit
	// on the send queue flushing the STREAM + FIN + CONNECTION_CLOSE
	// frames for many minutes because every send fails and
	// MaxIdleTimeout is fooled by the activity. Without a Write
	// deadline, the relay goroutine never exits, handleConn never
	// returns, and dae_active_connections stays pinned.
	DefaultTCPWriteTimeout = 8 * time.Second
)

func (c *ControlPlane) handleTcpDns(
	lConn net.Conn, src, dst netip.AddrPort, routingResult *bpfRoutingResult) error {
	var length uint16
	var err error
	var data []byte
	// Read dns request
	if err = binary.Read(lConn, binary.BigEndian, &length); err == nil {
		data = pool.GetBuffer(int(length))
		defer pool.PutBuffer(data)
		_, err = io.ReadFull(lConn, data)
	}
	if err != nil {
		log.Debugf("failed to read tcp dns request: %v", err)
		// It's common to get EOF when reading tcp dns request.
		return nil
	}
	id := dnsId(data)
	// Avoids duplicated id from clients, so make the id unique.
	dnsIdSet(data, uint16(fastrand.Intn(math.MaxUint16)))
	queryInfo := dnsQueryInfo(data)
	dq := ObtainDnsRequest(src, dst, routingResult, true)
	respData := dnsResponseDataPool.Get().(*dnsResponseData)
	if err = c.dnsController.handleDNSRequest(data, dq, queryInfo, respData); err != nil {
		log.Errorf("Failed to handle tcp dns request: %v", err)
		dnsRcodeSet(respData.respData, dnsmessage.RcodeServerFailure)
	}
	RecycleDnsRequest(dq)
	defer func() {
		if respData.respData != nil && respData.fromPool {
			pool.PutBuffer(respData.respData)
		}
		*respData = dnsResponseData{}
		dnsResponseDataPool.Put(respData)
	}()
	if len(respData.respData) == 0 {
		return nil
	}
	// Keep the id the same with request.
	dnsIdSet(respData.respData, id)
	if err = binary.Write(lConn, binary.BigEndian, uint16(len(respData.respData))); err == nil {
		if _, err = lConn.Write(respData.respData); err == nil {
			return nil
		}
	}
	return err
}

func (c *ControlPlane) handleConn(lConn net.Conn) error {
	// Get tuples and outbound.
	src := lConn.RemoteAddr().(*net.TCPAddr).AddrPort()
	dstTcpAddr := lConn.LocalAddr().(*net.TCPAddr)
	dst := dstTcpAddr.AddrPort()
	istcpdns := dstTcpAddr.Port == 53
	routingResult := ObtainBpfRoutingResult()
	defer func() {
		if routingResult != nil {
			RecycleBpfRoutingResult(routingResult)
		}
	}()

	if err := c.core.RetrieveTCPRoutingResult(src, dst, routingResult); err != nil {
		return common.Wrap(err, "failed to retrieve target info %v", dst.String())
	}

	defer c.core.closeRoutingTuplesEntry(src, dst, 6 /* IPPROTO_TCP */)

	src = common.ConvergeAddrPort(src)
	dst = common.ConvergeAddrPort(dst)
	if istcpdns {
		return c.handleTcpDns(lConn, src, dst, routingResult)
	}

	// No need sniffer for tcp://8.8.8.8:53.
	sniffedDomain := ""
	lConnRelay := lConn
	if c.sniffingTimeout > 0 {
		sniffingTimeout := c.sniffingTimeout
		if dstTcpAddr.Port == 80 || dstTcpAddr.Port == 443 {
			sniffingTimeout = 2 * sniffingTimeout
		}
		// Sniff target domain.
		sniffer := sniffing.NewConnSniffer(lConn, sniffingTimeout)
		// ConnSniffer should be used later, so we cannot close it now.
		defer sniffer.Close()

		lConn.SetReadDeadline(time.Now().Add(sniffingTimeout))
		domain, err := sniffer.SniffTcp()
		lConn.SetReadDeadline(time.Time{})
		if err != nil {
			// Avoid massive EOF logs. A common case: clients (e.g. browser) tend to establish both
			// ipv4 and ipv6 connections, and then close one of them.
			if errors.Is(err, io.EOF) {
				return nil
			}
			// In case of lConn timeout, we continue relaying for remote-first tcp conversation (e.g. ftp, smtp, etc.).
			// For other network errors, we stop relaying without logging the errors.
			if isNetError, _, isTimeout, _ := GetNetErrorInfo(err); isNetError {
				if !isTimeout {
					return nil
				}
				if log.IsLevelEnabled(log.InfoLevel) {
					log.Infof("Sniffing timeout!")
				}
			}
		}
		sniffedDomain = domain
		lConnRelay = sniffer
	}

	// Route
	networkType := common.GetNetworkType(consts.L4ProtoStr_TCP, dst.Addr())
	dialOption := ObtainDialOption()
	defer RecycleDialOption(dialOption)
	if err := c.RouteDialOption(src, dst, sniffedDomain, networkType, routingResult, dialOption); err != nil {
		return err
	}
	labels := [...]string{
		dialOption.Outbound.Name,
		dialOption.Dialer.Property.SubscriptionTag,
		dialOption.Dialer.Name,
		networkType.String(),
	}

	// Dial
	LogDial(src, dst, sniffedDomain, dialOption, networkType, routingResult)
	// routingResult is not used in following code, recycle it eariler.
	RecycleBpfRoutingResult(routingResult)
	routingResult = nil

	ctx, cancel := context.WithTimeout(context.TODO(), consts.DefaultDialTimeout)
	defer cancel()
	rConn, err := dialOption.Dialer.DialContext(ctx, "tcp", dialOption.DialTarget)
	if err != nil {
		// TODO: UDP 是不是也有Direct Outbound出问题的情况?
		// TODO: Control Plane Routing?
		// TODO: 哪些错误说明节点不工作或GFW在工作?
		// TCP: Connection Reset / Connection Refused
		isNetError, isClosed, isTimeout, isTemporary := GetNetErrorInfo(err)
		if isClosed {
			return nil
		}
		if !isNetError || (!isTimeout && dialOption.Dialer.NeedAliveState()) {
			err = common.
				In("DialContext").
				With("Is NetError", isNetError).
				With("Is Temporary", isTemporary).
				With("Is Timeout", isTimeout).
				With("Outbound", dialOption.Outbound.Name).
				With("Dialer", dialOption.Dialer.Name).
				With("src", src.String()).
				With("dst", dst.String()).
				With("domain", sniffedDomain).
				Wrapf(err, "failed to DialContext")
			if !isNetError {
				return err
			}
			// Must be !isTimeout && dialOption.Dialer.NeedAliveState()
			common.Metrics.ErrorCount.With4(labels).Inc()
			dialOption.Dialer.ReportUnavailable()
			return err
		}
		return nil
	}

	// Register the (lConnRelay, rConn) pair so that AbortConns can close
	// BOTH sides of the relay when the dialer transitions alive -> not
	// alive. Closing lConn is what unblocks a relay goroutine stuck in a
	// blocking Write(lConn); rConn close alone can't reach it.
	dialOption.Dialer.RegisterConn(lConnRelay, rConn)
	defer dialOption.Dialer.UnregisterConn(rConn)

	// Defensive: if the dialer flipped to not-alive between Select() and
	// RegisterConn, don't leave a "zombie" conn in the registry that would
	// only get cleaned up by the next AbortConns cycle. Bail immediately
	// instead. The defers above will still unregister rConn; we skip the
	// Inc/Dec pair entirely because the relay never actually started.
	// We also have to close lConnRelay ourselves here: the normal path
	// closes it via `defer rLogConn.Close()` (which is registered further
	// down), but that defer doesn't exist yet at this point in the flow,
	// so without an explicit Close the local socket would leak until GC
	// (and the client side would never see the close).
	//
	// Return a wrapped error rather than nil so this race is observable
	// in the log: the connection died for a known reason (dialer went
	// away), not because of an upstream/network failure. We do NOT bump
	// ErrorCount or call ReportUnavailable — the connectivity check
	// already did both when the dialer transitioned alive -> not-alive.
	if dialOption.Dialer.NeedAliveState() && !dialOption.Dialer.Alive() {
		rConn.Close()
		lConnRelay.Close()
		return common.Errf("conn discarded due to dialer %q (outbound=%q) became not-alive",
			dialOption.Dialer.Name, dialOption.Outbound.Name)
	}

	activeConnectionsCounter := common.Metrics.ActiveConnections.With4(labels)
	activeConnectionsCounter.Inc()
	defer activeConnectionsCounter.Dec()

	var onTraffic func(dir string, n int64)
	if c.trafficLogger != nil {
		srcStr := src.Addr().String()
		dstStr := dialOption.DialTarget
		onTraffic = func(dir string, n int64) {
			c.trafficLogger.Log(srcStr, dstStr, dir, n)
		}
	}
	rLogConn := NewTrafficLogConn(rConn, common.Metrics.TrafficBytes.With4(labels), onTraffic)
	defer rLogConn.Close()

	// Relay
	if err := RelayTCP(lConnRelay, rLogConn); err != nil {
		isNetError, isClosed, isTimeout, isTemporary := GetNetErrorInfo(err)
		if isClosed {
			return nil
		}
		if !isNetError || (!isTimeout && dialOption.Dialer.NeedAliveState()) {
			err = common.
				In("RelayTCP").
				With("Is NetError", isNetError).
				With("Is Temporary", isTemporary).
				With("Is Timeout", isTimeout).
				With("Outbound", dialOption.Outbound.Name).
				With("Dialer", dialOption.Dialer.Name).
				With("src", src.String()).
				With("dst", dst.String()).
				With("domain", sniffedDomain).
				Wrapf(err, "failed to RelayTCP")
			if !isNetError {
				return err
			}
			// Must be !isTimeout && dialOption.Dialer.NeedAliveState()
			common.Metrics.ErrorCount.With4(labels).Inc()
			dialOption.Dialer.ReportUnavailable()
			return err
		}
	}
	// case strings.HasSuffix(err.Error(), "write: broken pipe"),
	// 	strings.HasSuffix(err.Error(), "i/o timeout"),
	// 	strings.HasPrefix(err.Error(), "EOF"),
	// 	strings.HasSuffix(err.Error(), "connection reset by peer"),
	// 	strings.HasSuffix(err.Error(), "canceled by local with error code 0"),
	// 	strings.HasSuffix(err.Error(), "canceled by remote with error code 0"):
	return nil
}

func relayDirection(dst, src net.Conn) error {
	// As `io.Copy` uses a 32KB buffer.
	// See https://cs.opensource.google/go/go/+/refs/tags/go1.21.5:src/io/io.go;l=419
	// Uses a smaller buffer for less memory blooming. And 2K is enough for tcp dns.
	var err error
	bufSize := 2 * 1024 // initial 2K, the bufSize will dynamically increase as needed
	maxBufSize := 32 * 1024
	buf := pool.GetBuffer(bufSize)
	for {
		src.SetReadDeadline(time.Now().Add(DefaultTCPIdleTimeout))
		n, rerr := src.Read(buf)
		if n > 0 {
			dst.SetWriteDeadline(time.Now().Add(DefaultTCPWriteTimeout))
			_, werr := dst.Write(buf[:n])
			if werr != nil {
				if errors.Is(werr, net.ErrClosed) {
					err = nil
				} else {
					err = werr
				}
				break
			}
			bufSize = min(n*2, maxBufSize)
			if bufSize > len(buf) {
				pool.PutBuffer(buf)
				buf = pool.GetBuffer(bufSize)
			}
		}
		if rerr != nil {
			// Timeout / EOF / Closed is normal.
			// io.ErrClosedPipe is the canonical smux stream/session-closed
			// signal (multiplexed streams die in bulk when a session or a
			// dialer abort tears them down) — same normal-termination class
			// as a plain conn's EOF/net.ErrClosed.
			if netErr, ok := rerr.(net.Error); ok && netErr.Timeout() {
				err = nil
			} else if rerr == io.EOF || rerr == io.ErrClosedPipe {
				err = nil
			} else if errors.Is(rerr, net.ErrClosed) {
				err = nil
			} else {
				err = rerr
			}
			break
		}
	}
	pool.PutBuffer(buf)
	if err != nil {
		dst.Close()
	} else if writeCloser, ok := dst.(netproxy.CloseWriter); ok {
		writeCloser.CloseWrite()
	} else {
		dst.SetReadDeadline(time.Now().Add(10 * time.Second))
	}
	return err
}

// Error1 is the error from lConn to rConn
// Error2 is the error from rConn to lConn
func RelayTCP(lConn, rConn net.Conn) error {
	var (
		r2lErr   error
		l2rErr   error
		errState int32
		wg       sync.WaitGroup
	)
	wg.Go(func() {
		e := relayDirection(lConn, rConn) // rConn -> lConn
		if e != nil {
			if atomic.CompareAndSwapInt32(&errState, 0, 1) {
				r2lErr = e
			}
		}
	})
	e := relayDirection(rConn, lConn) // lConn -> rConn
	if e != nil {
		if atomic.CompareAndSwapInt32(&errState, 0, 2) {
			l2rErr = e
		}
	}
	wg.Wait()

	switch atomic.LoadInt32(&errState) {
	case 1: // r -> l
		errMsg := r2lErr.Error()
		switch {
		case strings.Contains(errMsg, "write:"): // lConn Write
			return nil
		case strings.HasSuffix(errMsg, "canceled by local with error code 0"),
			strings.HasSuffix(errMsg, "canceled by remote with error code 0"):
			return nil
		default:
			return common.In("rConn -> lConn Relay").Wrap(r2lErr)
		}
	case 2: // l -> r
		if l2rErr == io.EOF {
			return nil
		}
		errMsg := l2rErr.Error()
		switch {
		case strings.HasSuffix(errMsg, "canceled by remote with error code 0"), // rConn closed
			strings.Contains(errMsg, "read:"): // lConn Read
			return nil
		default:
			return common.In("lConn -> rConn Relay").Wrap(l2rErr)
		}
	}
	return nil
}
