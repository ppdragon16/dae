/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"context"
	"net/netip"
	"sync"
	"sync/atomic"

	"time"

	"github.com/daeuniverse/dae/common"
	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/component/sniffing"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/samber/oops"
	log "github.com/sirupsen/logrus"
)

var (
	// Values from OpenWRT default sysctl config
	DefaultNatTimeoutUDP = 90 * time.Second
)

const (
	AnyfromTimeout = 5 * time.Second // Do not cache too long.
)

// sendPkt uses bind first, and fallback to send hdr if addr is in use.
func sendPkt(data []byte, from, to netip.AddrPort) (err error) {
	uConn, _, err := DefaultAnyfromPool.GetOrCreate(from, AnyfromTimeout)
	if err != nil {
		return
	}
	_, err = uConn.WriteToUDPAddrPort(data, to)
	return err
}

type sniffedSessionValue struct {
	sniffedDomain string
	dealineTimer  *time.Timer
	replied       int32     // Just for logging
	createdAt     time.Time // Just for logging
}

var (
	sniffedSessionPool = sync.Map{}
)

const (
	sniffedSessionTtl = 60 * time.Second
)

func (c *ControlPlane) handlePkt(data []byte, src, dst netip.AddrPort) (err error) {
	var domain string

	/// Sniff
	if dst.Port() == 443 {
		// Sniff Quic, ...
		key := PacketSnifferKey{
			LAddr: src,
			RAddr: dst,
		}
		if v, ok := sniffedSessionPool.Load(key); ok {
			sniffedValue := v.(*sniffedSessionValue)
			domain = sniffedValue.sniffedDomain
			sniffedValue.dealineTimer.Reset(sniffedSessionTtl)
		} else {
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
				if err != nil && log.IsLevelEnabled(log.TraceLevel) {
					log.Tracef("%+v", oops.
						With("from", src).
						With("to", dst).
						Wrapf(err, "sniffUDP"))
				}
				// 1) In most cases, the first packet should be enough for SNI.
				// 2) Some clients, e.g. curl, may send 2 packets without SNI, but the sniffer still needs more.
				// We should NEVER hold packets and rehandle them after sniffing, because when sniffer needs more, the following packets may never come.
				// The first packet routing may be wrong (rely on correct kernel routing), but it's better than timeout.
				if !sniffer.NeedMore() {
					sniffedSessionPool.Store(key, &sniffedSessionValue{
						sniffedDomain: domain,
						createdAt:     time.Now(),
						dealineTimer: time.AfterFunc(sniffedSessionTtl, func() {
							sniffedSessionPool.Delete(key)
						}),
					})
					DefaultPacketSnifferSessionMgr.Remove(key, sniffer)
				}
			}
			_sniffer.Mu.Unlock()
		}
	}

	/// Dial and send.
	// TODO: Rewritten domain should not use full-cone (such as VMess Packet Addr).
	// 		Maybe we should set up a mapping for UDP: Dialer + Target Domain => Remote Resolved IP.
	//		However, games may not use QUIC for communication, thus we cannot use domain to dial, which is fine.
	networkType := &common.NetworkType{
		L4Proto:   consts.L4ProtoStr_UDP,
		IpVersion: consts.IpVersionStrFromAddr(dst.Addr()),
	}

	l, _ := DefaultUdpEndpointPool.UdpEndpointKeyLocker.Lock(src)
	defer DefaultUdpEndpointPool.UdpEndpointKeyLocker.Unlock(src, l)

	// Get udp endpoint.
	ue, ok := DefaultUdpEndpointPool.Get(src)
	// If the udp endpoint has been not alive, remove it from pool and retry
	// UDP 不是面向连接的, 在 tcp 中, 一个连接失败, 我们会重置中继它, 等待一个新的连接
	// 在 UDP 中, l -> r继续中继到新的节点, 并在新的节点上进行 r -> l 中继
	if ok && !ue.dialer.Alive() {
		if log.IsLevelEnabled(log.DebugLevel) {
			log.WithFields(log.Fields{
				"src":     RefineSourceToShow(src, dst.Addr()),
				"network": networkType.String(),
				"dialer":  ue.dialer.Name,
			}).Debugln("Old udp endpoint was not alive and removed.")
		}
		_ = DefaultUdpEndpointPool.Remove(src)
		ok = false
	}
	if !ok {
		// Use an empty AddrPort for dst
		var routingResult bpfRoutingResult
		if err := c.core.RetrieveUDPRoutingResult(src, &routingResult); err != nil {
			return oops.Wrapf(err, "No AddrPort presented")
		}

		// Route
		dialOption, err := c.RouteDialOption(src, dst, domain, networkType, &routingResult)
		if err != nil {
			return err
		}

		labels := prometheus.Labels{
			"outbound": dialOption.Outbound.Name,
			"subtag":   dialOption.Dialer.Property.SubscriptionTag,
			"dialer":   dialOption.Dialer.Name,
			"network":  networkType.String(),
		}

		// Dial
		ctx, cancel := context.WithTimeout(context.TODO(), consts.DefaultDialTimeout)
		defer cancel()
		// Do not overwrite target.
		// This fixes a problem that quic connection to google servers.
		// Reproduce:
		// docker run --rm --name curl-http3 ymuski/curl-http3 curl --http3 -o /dev/null -v -L https://i.ytimg.com
		udpConn, err := dialOption.Dialer.ListenPacket(ctx, dst.String())
		if err != nil {
			netErr, ok := IsNetError(err)
			err = oops.
				In("ListenPacket").
				With("Is NetError", ok).
				With("Is Temporary", ok && netErr.Temporary()).
				With("Is Timeout", ok && netErr.Timeout()).
				With("Outbound", dialOption.Outbound.Name).
				With("Dialer", dialOption.Dialer.Name).
				With("src", src.String()).
				With("dst", dst.String()).
				With("domain", domain).
				Wrapf(err, "failed to ListenPacket")
			if !ok {
				return err
			} else if !netErr.Timeout() {
				if dialOption.Dialer.NeedAliveState() {
					common.ErrorCount.With(labels).Inc()
					dialOption.Dialer.ReportUnavailable()
					return err
				}
			}
			return nil
		}
		ue = DefaultUdpEndpointPool.Create(src, &UdpEndpointOptions{
			PacketConn: udpConn,
			Handler: func(data []byte, from netip.AddrPort) (err error) {
				// Only print routing for new connection to avoid the log exploded (Quic and BT).
				// Note: Log dialOption.dialTarget but dial dst.string().
				shouldLog := false
				logDomain := ""
				if v, ok := sniffedSessionPool.Load(PacketSnifferKey{LAddr: src, RAddr: from}); ok {
					value := v.(*sniffedSessionValue)
					if atomic.CompareAndSwapInt32(&value.replied, 0, 1) {
						shouldLog = true
						logDomain = value.sniffedDomain
						if log.IsLevelEnabled(log.InfoLevel) {
							log.Infof("UDP first response latency: %vms", time.Since(value.createdAt).Milliseconds())
						}
					}
				} else {
					shouldLog = true
				}
				if shouldLog {
					LogDial(src, dst, logDomain, dialOption, networkType, &routingResult)
				}
				return sendPkt(data, from, src)
			},
			NatTimeout: DefaultNatTimeoutUDP,
			Dialer:     dialOption.Dialer,
			labels:     labels,
		})
		// Receive UDP messages.
		go func() {
			err = ue.run()
			DefaultUdpEndpointPool.Remove(src)
			if err != nil {
				netErr, ok := IsNetError(err)
				err = oops.
					In("UdpEndpoint r -> l relay").
					With("Is NetError", ok).
					With("Is Temporary", ok && netErr.Temporary()).
					With("Is Timeout", ok && netErr.Timeout()).
					With("Dialer", ue.dialer.Name).
					Wrap(err)
				if !ok {
					log.Warnf("%+v", err)
				} else if !netErr.Timeout() {
					if ue.dialer.NeedAliveState() {
						common.ErrorCount.With(labels).Inc()
						ue.dialer.ReportUnavailable()
						log.Warnf("%+v", err)
					}
				}
			}
		}()
	}

	// TODO: What is realSrc/Dst?
	// Try to write data
	_, err = ue.WriteTo(data, dst)
	if err != nil {
		DefaultUdpEndpointPool.Remove(src)
		netErr, ok := IsNetError(err)
		err = oops.
			In("UdpEndpoint l -> r relay").
			With("Is NetError", ok).
			With("Is Temporary", ok && netErr.Temporary()).
			With("Is Timeout", ok && netErr.Timeout()).
			With("Dialer", ue.dialer.Name).
			Wrapf(err, "failed to write UDP packet")
		if !ok {
			return err
		} else if !netErr.Timeout() {
			if ue.dialer.NeedAliveState() {
				common.ErrorCount.With(ue.labels).Inc()
				ue.dialer.ReportUnavailable()
				return err
			}
		}
	}
	return nil
}
