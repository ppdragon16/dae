/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"context"
	"errors"
	"net"
	"net/netip"

	"time"

	"github.com/daeuniverse/dae/common"
	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/component/outbound/dialer"
	"github.com/daeuniverse/dae/component/sniffing"
	"github.com/daeuniverse/outbound/netproxy"
	"github.com/daeuniverse/outbound/pool"
	dnsmessage "github.com/miekg/dns"
	"github.com/samber/oops"
	log "github.com/sirupsen/logrus"
)

var (
	// Values from OpenWRT default sysctl config
	DefaultNatTimeoutTCP = 5 * time.Minute
	DefaultNatTimeoutUDP = 90 * time.Second
)

const (
	DnsNatTimeout  = 17 * time.Second // RFC 5452
	AnyfromTimeout = 5 * time.Second  // Do not cache too long.
	MaxRetry       = 2
)

type UdpEndpointKey struct {
	LAddr netip.AddrPort
	RAddr netip.AddrPort
}

func ChooseNatTimeout(data []byte, sniffDns bool) (dmsg *dnsmessage.Msg, timeout time.Duration) {
	if sniffDns {
		var dnsmsg dnsmessage.Msg
		if err := dnsmsg.Unpack(data); err == nil {
			//log.Printf("DEBUG: lookup %v", dnsmsg.Question[0].Name)
			return &dnsmsg, DnsNatTimeout
		}
	}
	return nil, DefaultNatTimeoutUDP
}

// sendPkt uses bind first, and fallback to send hdr if addr is in use.
func sendPkt(data []byte, from, to netip.AddrPort) (err error) {
	uConn, _, err := DefaultAnyfromPool.GetOrCreate(from, AnyfromTimeout)
	if err != nil {
		return
	}
	_, err = uConn.WriteToUDPAddrPort(data, to)
	return err
}

func (c *ControlPlane) handlePkt(lConn *net.UDPConn, data []byte, src, dst netip.AddrPort, routingResult *bpfRoutingResult, skipSniffing bool) (err error) {
	var domain string

	/// Handle DNS
	// To keep consistency with kernel program, we only sniff DNS request sent to 53.
	dnsMessage, natTimeout := ChooseNatTimeout(data, dst.Port() == 53)
	// We should cache DNS records and set record TTL to 0, in order to monitor the dns req and resp in real time.
	isDns := dnsMessage != nil && routingResult.Must == 0 // Regard as plain traffic
	// TODO: 重复逻辑
	if routingResult.Mark == 0 {
		routingResult.Mark = c.soMarkFromDae
	}
	if isDns {
		return c.dnsController.Handle(dnsMessage, &udpRequest{
			src:           src,
			dst:           dst,
			lConn:         lConn,
			routingResult: routingResult,
		})
	}

	key := UdpEndpointKey{
		LAddr: src,
		RAddr: dst,
	}

	/// Sniff
	if !skipSniffing {
		// Sniff Quic, ...
		_sniffer, _ := DefaultPacketSnifferSessionMgr.GetOrCreate(key, nil)
		_sniffer.Mu.Lock()
		// Re-get sniffer from pool to confirm the transaction is not done.
		sniffer := DefaultPacketSnifferSessionMgr.Get(key)
		if _sniffer == sniffer {
			sniffer.AppendData(data)
			domain, err = sniffer.SniffUdp()
			if err != nil && !sniffing.IsSniffingError(err) {
				sniffer.Mu.Unlock()
				return oops.
					With("from", src).
					With("to", dst).
					Wrapf(err, "sniffUDP non sniffing error")
			}
			if sniffer.NeedMore() {
				sniffer.Mu.Unlock()
				return nil
			}
			if err != nil && log.IsLevelEnabled(log.TraceLevel) {
				log.Tracef("%+v", oops.
					With("from", src).
					With("to", dst).
					Wrapf(err, "sniffUDP"))
			}
			defer DefaultPacketSnifferSessionMgr.Remove(key, sniffer)
			// Re-handlePkt after self func.
			toRehandle := sniffer.Data()[1 : len(sniffer.Data())-1] // Skip the first empty and the last (self).
			sniffer.Mu.Unlock()
			if len(toRehandle) > 0 {
				defer func() {
					if err == nil {
						for _, d := range toRehandle {
							dCopy := pool.Get(len(d))
							copy(dCopy, d)
							go c.handlePkt(lConn, dCopy, src, dst, routingResult, true)
							// TODO: error?
						}
					}
				}()
			}
		} else {
			_sniffer.Mu.Unlock()
			// sniffer may be nil.
		}
	}

	/// Dial and send.
	// TODO: Rewritten domain should not use full-cone (such as VMess Packet Addr).
	// 		Maybe we should set up a mapping for UDP: Dialer + Target Domain => Remote Resolved IP.
	//		However, games may not use QUIC for communication, thus we cannot use domain to dial, which is fine.

	// Retry loop for UDP endpoint creation and writing
	// for retry := 1; retry <= MaxRetry; retry++ {
	// 	if retry > 0 {
	// 		// Log retry atteWriteTompt
	// 		if c.log.IsLevelEnabled(logrus.DebugLevel) {
	// 			c.log.WithFields(logrus.Fields{
	// 				"src":     RefineSourceToShow(realSrc, realDst.Addr()),
	// 				"network": networkType.String(),
	// 				"retry":   retry,
	// 			}).Debugln("Retrying UDP endpoint creation/write...")
	// 		}
	// 	}

	networkType := &dialer.NetworkType{
		L4Proto:   consts.L4ProtoStr_UDP,
		IpVersion: consts.IpVersionFromAddr(dst.Addr()),
		IsDns:     false,
	}

	l := DefaultUdpEndpointPool.UdpEndpointKeyLocker.Lock(key)
	defer DefaultUdpEndpointPool.UdpEndpointKeyLocker.Unlock(key, l)

	// Get udp endpoint.
	ue, ok := DefaultUdpEndpointPool.Get(key)
	// If the udp endpoint has been not alive, remove it from pool and retry
	// UDP 不是面向连接的, 在 tcp 中, 一个连接失败, 我们会重置中继它, 等待一个新的连接
	// 在 UDP 中, l -> r继续中继到新的节点, 并在新的节点上进行 r -> l 中继
	if ok && !ue.dialer.MustGetAlive(networkType) {
		if log.IsLevelEnabled(log.DebugLevel) {
			log.WithFields(log.Fields{
				"src":     RefineSourceToShow(src, dst.Addr()),
				"network": networkType.String(),
				"dialer":  ue.dialer.Property().Name,
			}).Debugln("Old udp endpoint was not alive and removed.")
		}
		_ = DefaultUdpEndpointPool.Remove(key)
		ok = false
	}
	if !ok {
		// Route
		dialOption, err := c.RouteDialOption(&RouteParam{
			routingResult: routingResult,
			networkType:   networkType,
			Domain:        domain,
			Src:           src,
			Dest:          dst,
		})
		if err != nil {
			return err
		}

		// Dial
		// Only print routing for new connection to avoid the log exploded (Quic and BT).
		LogDial(src, dst, domain, dialOption, networkType, routingResult)
		// Do not overwrite target.
		// This fixes a problem that quic connection to google servers.
		// Reproduce:
		// docker run --rm --name curl-http3 ymuski/curl-http3 curl --http3 -o /dev/null -v -L https://i.ytimg.com
		ctx, cancel := context.WithTimeout(context.TODO(), consts.DefaultDialTimeout)
		defer cancel()
		udpConn, err := dialOption.Dialer.DialContext(ctx, common.MagicNetwork("udp", dialOption.Mark), dst.String())
		if err != nil {
			var netErr net.Error
			if errors.As(err, &netErr) && !netErr.Temporary() {
				err = oops.
					In("DialContext").
					With("Is NetError", errors.As(err, &netErr)).
					With("Is Temporary", netErr != nil && netErr.Temporary()).
					With("Is Timeout", netErr != nil && netErr.Timeout()).
					With("Outbound", dialOption.Outbound.Name).
					With("Dialer", dialOption.Dialer.Property().Name).
					With("src", src.String()).
					With("dst", dst.String()).
					With("domain", domain).
					With("routingResult", routingResult).
					Wrapf(err, "failed to DialContext")
				dialOption.Dialer.ReportUnavailable(networkType, err)
				if !dialOption.OutboundIndex.IsReserved() {
					return err
				}
			}
			return nil
		}
		ue = DefaultUdpEndpointPool.Create(key, &UdpEndpointOptions{
			PacketConn: udpConn.(netproxy.PacketConn),
			Handler: func(data []byte, from netip.AddrPort) (err error) {
				return sendPkt(data, from, src)
			},
			NatTimeout: natTimeout,
			Dialer:     dialOption.Dialer,
		})
		// Receive UDP messages.
		go func() {
			err = ue.run()
			DefaultUdpEndpointPool.Remove(key)
			if err != nil {
				var netErr net.Error
				if errors.As(err, &netErr) && !netErr.Temporary() && ue.dialer.MustGetAlive(networkType) {
					err = oops.
						In("UdpEndpoint r -> l relay").
						With("Is NetError", errors.As(err, &netErr)).
						With("Is Temporary", netErr != nil && netErr.Temporary()).
						With("Is Timeout", netErr != nil && netErr.Timeout()).
						With("Dialer", ue.dialer.Property().Name).
						Wrap(err)
					ue.dialer.ReportUnavailable(networkType, err)
					if !dialOption.OutboundIndex.IsReserved() {
						log.Warnf("%+v", err)
					}
				}
			}
		}()
	}

	// TODO: What is realSrc/Dst?
	// Try to write data
	_, err = ue.WriteTo(data, dst.String())
	if err != nil {
		_ = DefaultUdpEndpointPool.Remove(key)

		var netErr net.Error
		if errors.As(err, &netErr) && !netErr.Temporary() {
			err = oops.
				In("UdpEndpoint l -> r relay").
				In("UDP WriteTo").
				With("Is NetError", errors.As(err, &netErr)).
				With("Is Temporary", netErr != nil && netErr.Temporary()).
				With("Is Timeout", netErr != nil && netErr.Timeout()).
				With("Dialer", ue.dialer.Property().Name).
				Wrapf(err, "failed to write UDP packet")
			ue.dialer.ReportUnavailable(networkType, err)
			return err
		}
	}

	// // Print log.
	// // Only print routing for new connection to avoid the log exploded (Quic and BT).
	// if (isNew && c.log.IsLevelEnabled(logrus.InfoLevel)) || c.log.IsLevelEnabled(logrus.DebugLevel) {
	// 	fields := logrus.Fields{
	// 		"network":  networkType.StringWithoutDns(),
	// 		"outbound": ue.Outbound.Name,
	// 		"policy":   ue.Outbound.GetSelectionPolicy(),
	// 		"dialer":   ue.Dialer.Property().Name,
	// 		"sniffed":  domain,
	// 		"ip":       RefineAddrPortToShow(realDst),
	// 		"pid":      routingResult.Pid,
	// 		"ifindex":  routingResult.Ifindex,
	// 		"dscp":     routingResult.Dscp,
	// 		"pname":    ProcessName2String(routingResult.Pname[:]),
	// 		"mac":      Mac2String(routingResult.Mac[:]),
	// 	}
	// 	logger := c.log.WithFields(fields).Infof
	// 	if !isNew && c.log.IsLevelEnabled(logrus.DebugLevel) {
	// 		logger = c.log.WithFields(fields).Debugf
	// 	}
	// 	logger("[%v] %v <-> %v", strings.ToUpper(networkType.String()), RefineSourceToShow(realSrc, realDst.Addr()), dialTarget)
	// }
	return nil
}
