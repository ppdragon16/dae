/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"context"
	"net/netip"

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

type sniffingResult struct {
	domain  string
	pending [][]byte
	ignored bool
}

func (c *ControlPlane) sniffPkt(
	key PacketSnifferKey, data []byte, src, dst netip.AddrPort) (result *sniffingResult, err error) {
	if dst.Port() != 443 {
		return &sniffingResult{ignored: true}, nil
	}
	var domain string
	// Sniff Quic, ...
	sniffer, _ := DefaultPacketSnifferSessionMgr.GetOrCreate(key, nil)
	sniffer.Mu.Lock()
	defer sniffer.Mu.Unlock()
	sniffer.AppendData(data)
	domain, err = sniffer.SniffUdp()
	if err != nil && !sniffing.IsSniffingError(err) {
		return nil, oops.
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
	if !sniffer.NeedMore() {
		result = &sniffingResult{
			domain: domain,
			// Skip the first empty and the last (self).
			pending: sniffer.Data()[1 : len(sniffer.Data())-1],
		}
	}
	return result, nil
}

func (c *ControlPlane) createUdpEndpoint(
	ueKey UdpEndpointKey, data []byte, src, dst netip.AddrPort) (ue *UdpEndpoint, err error) {
	networkType := &common.NetworkType{
		L4Proto:   consts.L4ProtoStr_UDP,
		IpVersion: consts.IpVersionStrFromAddr(dst.Addr()),
	}
	var sniffingResult *sniffingResult
	sniffkey := PacketSnifferKey{LAddr: src, RAddr: dst}
	sniffingResult, err = c.sniffPkt(sniffkey, data, src, dst)
	if sniffingResult == nil {
		return nil, err
	}
	// Use an empty AddrPort for dst
	var routingResult bpfRoutingResult
	if err := c.core.RetrieveUDPRoutingResult(src, &routingResult); err != nil {
		return nil, oops.Wrapf(err, "No AddrPort presented")
	}

	// Route
	dialOption, err := c.RouteDialOption(src, dst, sniffingResult.domain, networkType, &routingResult)
	if err != nil {
		return nil, err
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
			With("domain", sniffingResult.domain).
			Wrapf(err, "failed to ListenPacket")
		if !ok {
			return nil, err
		} else if !netErr.Timeout() {
			if dialOption.Dialer.NeedAliveState() {
				common.ErrorCount.With(labels).Inc()
				dialOption.Dialer.ReportUnavailable()
				return nil, err
			}
		}
		return nil, nil
	}
	ue = DefaultUdpEndpointPool.Create(ueKey, &UdpEndpointOptions{
		PacketConn: udpConn,
		Handler: func(data []byte, from netip.AddrPort) (err error) {
			// Only print routing for new connection to avoid the log exploded (Quic and BT).
			// Note: Log dialOption.dialTarget but dial dst.string().
			if !ue.receivedReply {
				LogDial(src, dst, ue.sniffedDomain, dialOption, networkType, &routingResult)
			}
			return sendPkt(data, from, src)
		},
		InitNatTimeout:  30 * time.Second,
		BonusNatTimeout: DefaultNatTimeoutUDP,
		BonusTraffic:    1024 * 1024, // 1MB traffic will extend BonusNatTimeout
		Dialer:          dialOption.Dialer,
		labels:          labels,
		SniffedDomain:   sniffingResult.domain,
	})
	// Receive UDP messages.
	go func() {
		err = ue.run()
		DefaultUdpEndpointPool.Remove(ueKey)
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
	if !sniffingResult.ignored {
		for _, d := range sniffingResult.pending {
			if _, err := ue.WriteTo(d, dst); err != nil {
				log.Warnf("%+v", oops.Wrapf(err, "write pending data"))
			}
		}
		DefaultPacketSnifferSessionMgr.Remove(sniffkey)
	}
	return ue, nil
}

func (c *ControlPlane) handlePkt(data []byte, src, dst netip.AddrPort) (err error) {
	ueKey := UdpEndpointKey{Src: src, Dst: dst}
	l, _ := DefaultUdpEndpointPool.UdpEndpointKeyLocker.Lock(ueKey)
	defer DefaultUdpEndpointPool.UdpEndpointKeyLocker.Unlock(ueKey, l)

	// Get udp endpoint.
	ue, ok := DefaultUdpEndpointPool.Get(ueKey)
	// If the udp endpoint has been not alive, remove it from pool and retry
	// UDP 不是面向连接的, 在 tcp 中, 一个连接失败, 我们会重置中继它, 等待一个新的连接
	// 在 UDP 中, l -> r继续中继到新的节点, 并在新的节点上进行 r -> l 中继
	if ok && !ue.dialer.Alive() {
		if log.IsLevelEnabled(log.DebugLevel) {
			log.WithFields(log.Fields{
				"src":    RefineSourceToShow(src, dst.Addr()),
				"dialer": ue.dialer.Name,
			}).Debugln("Old udp endpoint was not alive and removed.")
		}
		_ = DefaultUdpEndpointPool.Remove(ueKey)
		ok = false
	}
	if !ok {
		ue, err = c.createUdpEndpoint(ueKey, data, src, dst)
		if ue == nil {
			return err
		}
	}

	// Try to write data
	_, err = ue.WriteTo(data, dst)
	if err != nil {
		DefaultUdpEndpointPool.Remove(ueKey)
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
