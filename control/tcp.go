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
	DefaultTCPIdleTimeout = 60 * time.Minute
)

func readDnsMsg(r io.Reader) (*dnsmessage.Msg, error) {
	var length uint16
	if err := binary.Read(r, binary.BigEndian, &length); err != nil {
		return nil, err
	}
	m := pool.GetBuffer(int(length))
	defer pool.PutBuffer(m)
	if _, err := io.ReadFull(r, m); err != nil {
		return nil, err
	}
	msg := new(dnsmessage.Msg)
	if err := msg.Unpack(m); err != nil {
		return nil, err
	}
	return msg, nil
}

func writeDnsMsg(msg *dnsmessage.Msg, w io.Writer) error {
	buf := pool.GetBuffer(512)
	defer pool.PutBuffer(buf)
	res, err := msg.PackBuffer(buf)
	if err != nil {
		return err
	}
	if err = binary.Write(w, binary.BigEndian, uint16(len(res))); err == nil {
		if _, err = w.Write(res); err == nil {
			return nil
		}
	}
	return err
}

func (c *ControlPlane) handleTcpDns(
	lConn net.Conn, src, dst netip.AddrPort, routingResult *bpfRoutingResult) error {
	msg, err := readDnsMsg(lConn)
	if err != nil {
		log.Debugf("failed to read tcp dns request: %v", err)
		// It's common to get EOF when reading tcp dns request.
		return nil
	}

	id := msg.Id
	// Avoids duplicated id from clients, so make the id unique.
	msg.Id = uint16(fastrand.Intn(math.MaxUint16))
	queryInfo := c.dnsController.prepareQueryInfo(msg)
	dq := ObtainDnsRequest(src, dst, routingResult, true)
	if err = c.dnsController.handleDNSRequest(msg, dq, queryInfo); err != nil {
		log.Errorf("Failed to handle tcp dns request: %v", err)
		msg.Response = true
		msg.SetRcode(msg, dnsmessage.RcodeServerFailure)
	}
	RecycleDnsRequest(dq)

	// Keep the id the same with request.
	msg.Id = id
	if err = writeDnsMsg(msg, lConn); err != nil {
		return common.Wrap(err, "failed to write tcp dns response")
	}
	return nil
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

	src = common.ConvergeAddrPort(src)
	dst = common.ConvergeAddrPort(dst)
	if istcpdns {
		return c.handleTcpDns(lConn, src, dst, routingResult)
	}

	// No need sniffer for tcp://8.8.8.8:53.
	sniffedDomain := ""
	lConnRelay := lConn
	if dstTcpAddr.Port != 53 && c.sniffingTimeout > 0 {
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
			if netErr, ok := IsNetError(err); ok {
				if !netErr.Timeout() {
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
	labels := common.GetPrometheusLabels(
		dialOption.Outbound.Name,
		dialOption.Dialer.Property.SubscriptionTag,
		dialOption.Dialer.Name,
		networkType.String())

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
		netErr, ok := IsNetError(err)
		if !ok || (!netErr.Timeout() && dialOption.Dialer.NeedAliveState()) {
			err = common.
				In("DialContext").
				With("Is NetError", ok).
				With("Is Temporary", ok && netErr.Temporary()).
				With("Is Timeout", ok && netErr.Timeout()).
				With("Outbound", dialOption.Outbound.Name).
				With("Dialer", dialOption.Dialer.Name).
				With("src", src.String()).
				With("dst", dst.String()).
				With("domain", sniffedDomain).
				Wrapf(err, "failed to DialContext")
			if !ok {
				return err
			} else if !netErr.Timeout() && dialOption.Dialer.NeedAliveState() {
				common.ErrorCount.With(labels).Inc()
				dialOption.Dialer.ReportUnavailable()
				return err
			}
		}
		return nil
	}

	activeConnectionsCounter := common.ActiveConnections.With(labels)
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
	rLogConn := NewTrafficLogConn(rConn, common.TrafficBytes.With(labels), onTraffic)
	defer rLogConn.Close()

	// Relay
	if err := RelayTCP(lConnRelay, rLogConn); err != nil {
		netErr, ok := IsNetError(err)
		if !ok || (!netErr.Timeout() && dialOption.Dialer.NeedAliveState()) {
			err = common.
				In("RelayTCP").
				With("Is NetError", ok).
				With("Is Temporary", ok && netErr.Temporary()).
				With("Is Timeout", ok && netErr.Timeout()).
				With("Outbound", dialOption.Outbound.Name).
				With("Dialer", dialOption.Dialer.Name).
				With("src", src.String()).
				With("dst", dst.String()).
				With("domain", sniffedDomain).
				Wrapf(err, "failed to RelayTCP")
			if !ok {
				return err
			} else if !netErr.Timeout() && dialOption.Dialer.NeedAliveState() {
				common.ErrorCount.With(labels).Inc()
				dialOption.Dialer.ReportUnavailable()
				return err
			}
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

type relayResult struct {
	err       error
	direction bool // true for lConn->rConn, false for rConn->lConn
}

func relayDirection(dst, src net.Conn, direction bool) error {
	// As `io.Copy` uses a 32KB buffer.
	// See https://cs.opensource.google/go/go/+/refs/tags/go1.21.5:src/io/io.go;l=419
	// Uses a smaller buffer for less memory blooming. And 2K is enough for tcp dns.
	var err error
	bufSize := 2 * 1024 // initial 2K, the bufSize will dynamically increase as needed
	maxBufSize := 32 * 1024
	for {
		src.SetReadDeadline(time.Now().Add(DefaultTCPIdleTimeout))
		buf := pool.GetBuffer(bufSize)
		n, rerr := src.Read(buf)
		if n > 0 {
			_, werr := dst.Write(buf[:n])
			pool.PutBuffer(buf)
			if werr != nil {
				err = werr
				break
			}
			bufSize = min(n*2, maxBufSize)
		} else {
			pool.PutBuffer(buf)
		}
		if rerr != nil {
			// Timeout / EOF is normal.
			if netErr, ok := rerr.(net.Error); ok && netErr.Timeout() {
				err = nil
			} else if rerr == io.EOF {
				err = nil
			} else {
				err = rerr
			}
			break
		}
	}
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
// TODO: 引入 ctx, 在 dialer 不可用时取消 relay
// 进一步的, 给 lConn 发送 rst
func RelayTCP(lConn, rConn net.Conn) error {
	var (
		r2lErr   error
		l2rErr   error
		errState int32
		wg       sync.WaitGroup
	)
	wg.Go(func() {
		e := relayDirection(lConn, rConn, false) // rConn -> lConn
		if e != nil {
			if atomic.CompareAndSwapInt32(&errState, 0, 1) {
				r2lErr = e
			}
		}
	})
	e := relayDirection(rConn, lConn, true) // lConn -> rConn
	if e != nil {
		if atomic.CompareAndSwapInt32(&errState, 0, 2) {
			l2rErr = e
		}
	}
	wg.Wait()

	switch atomic.LoadInt32(&errState) {
	case 1: // r -> l
		switch {
		case strings.Contains(r2lErr.Error(), "write:"): // lConn Write
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
