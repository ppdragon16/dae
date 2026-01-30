/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"strings"
	"structs"
	"syscall"
	"time"

	"github.com/daeuniverse/dae/common"
	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/component/outbound"
	"github.com/daeuniverse/dae/component/outbound/dialer"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/samber/oops"
	log "github.com/sirupsen/logrus"
	"golang.org/x/sys/unix"
)

type DialOption struct {
	DialTarget        string
	Dialer            *dialer.Dialer
	Outbound          *outbound.DialerGroup
	FallbackIpVersion bool
	FallbackDialer    bool
	// Mark          uint32
}

func IsNetError(err error) (netErr net.Error, ok bool) {
	ok = errors.As(err, &netErr)
	return
}

func (c *ControlPlane) RecycleDialOption(dialOption *DialOption) {
	dialOption.DialTarget = ""
	dialOption.Dialer = nil
	dialOption.Outbound = nil
	dialOption.FallbackIpVersion = false
	dialOption.FallbackDialer = false
	// dialOption.Mark = 0
	c.dialOptionPool.Put(dialOption)
}

func (c *ControlPlane) RouteDialOption(
	src, dst netip.AddrPort,
	domain string,
	networkType *common.NetworkType,
	routingResult *bpfRoutingResult) (dialOption *DialOption, err error) {
	// TODO: Why not directly transfer routingResult
	outboundIndex := consts.OutboundIndex(routingResult.Outbound)
	// mark := p.routingResult.Mark

	verified, shouldReroute := c.VerifySniff(outboundIndex, dst, domain)
	switch {
	case c.rerouteMode == consts.RerouteMode_WhileNeed && shouldReroute != nil && shouldReroute(),
		c.rerouteMode == consts.RerouteMode_Force:
		outboundIndex = consts.OutboundControlPlaneRouting
	}

	switch outboundIndex {
	case consts.OutboundDirect:
	case consts.OutboundControlPlaneRouting:
		domain_ := domain
		if !verified {
			domain_ = ""
		}
		// if outboundIndex, mark, _, err = c.Route(p.Src, p.Dest, p.Domain, p.networkType.L4Proto.ToL4ProtoType(), p.routingResult); err != nil {
		if outboundIndex, _, _, err = c.Route(src, dst, domain_, networkType.L4Proto.ToL4ProtoType(), routingResult); err != nil {
			oops.Wrap(err)
			return
		}
		if log.IsLevelEnabled(log.TraceLevel) {
			log.Tracef("outbound: %v => <Control Plane Routing>",
				outboundIndex.String(),
			)
		}
	default:
	}
	// if mark == 0 {
	// 	mark = c.soMarkFromDae
	// }
	// TODO: Set-up ip to domain mapping and show domain if possible.
	if int(outboundIndex) >= len(c.outbounds) {
		if len(c.outbounds) == int(consts.OutboundUserDefinedMin) {
			err = oops.Errorf("traffic was dropped due to no-load configuration")
			return
		}
		err = oops.Errorf("outbound id from bpf is out of range: %v not in [0, %v]", outboundIndex, len(c.outbounds)-1)
		return
	}
	// Handles outbound redirects
	if redirected, exists := c.outboundRedirects[outboundIndex]; exists {
		outboundIndex = redirected
	}
	outbound := c.outbounds[outboundIndex]
	dialTarget, dialIp := c.ChooseDialTarget(outboundIndex, dst, domain, verified && c.dialTargetOverride)
	dialer, fallback, err := outbound.SelectFallbackIpVersion(networkType, dialIp)
	fallbackDialer := false
	if err != nil {
		dialer, err = c.outbounds[c.noConnectivityOutbound].Select(networkType)
		if err != nil {
			panic(fmt.Sprintf("fail to get fallback dialer %v(%v): %v", c.outbounds[c.noConnectivityOutbound], c.noConnectivityOutbound, err))
		}
		fallbackDialer = true
	}
	option := c.dialOptionPool.Get().(*DialOption)
	option.DialTarget = dialTarget
	option.Dialer = dialer
	option.Outbound = outbound
	option.FallbackIpVersion = fallback
	option.FallbackDialer = fallbackDialer
	// option.Mark = mark
	return option, nil
}

type TrafficLogConn struct {
	net.Conn
	logger       *TrafficLogger
	src, dst     string
	readBytes    int64
	writtenBytes int64
	counter      prometheus.Counter
	flushTimer   *time.Timer
	interval     time.Duration
}

func NewTrafficLogConn(conn net.Conn, logger *TrafficLogger, counter prometheus.Counter, src, dst string) *TrafficLogConn {
	return &TrafficLogConn{
		Conn:     conn,
		src:      src,
		dst:      dst,
		logger:   logger,
		counter:  counter,
		interval: 15 * time.Second,
	}
}

func (tc *TrafficLogConn) flush() {
	if tc.readBytes > 0 {
		tc.counter.Add(float64(tc.readBytes))
		tc.readBytes = 0
	}
	if tc.writtenBytes > 0 {
		tc.counter.Add(float64(tc.writtenBytes))
		tc.writtenBytes = 0
	}
	tc.flushTimer = nil
}

func (tc *TrafficLogConn) Read(p []byte) (int, error) {
	n, err := tc.Conn.Read(p)
	tc.readBytes += int64(n)
	if tc.flushTimer == nil {
		tc.flushTimer = time.AfterFunc(tc.interval, tc.flush)
	}
	if tc.logger != nil {
		tc.logger.Log(tc.src, tc.dst, "down", int64(n))
	}
	return n, err
}

func (tc *TrafficLogConn) Write(p []byte) (int, error) {
	n, err := tc.Conn.Write(p)
	tc.writtenBytes += int64(n)
	if tc.flushTimer == nil {
		tc.flushTimer = time.AfterFunc(tc.interval, tc.flush)
	}
	if tc.logger != nil {
		tc.logger.Log(tc.src, tc.dst, "up", int64(n))
	}
	return n, err
}

func (tc *TrafficLogConn) Close() error {
	if tc.flushTimer != nil {
		tc.flushTimer.Stop()
		tc.flush()
	}
	return tc.Conn.Close()
}

func LogDial(src, dst netip.AddrPort, domain string, dialOption *DialOption, networkType *common.NetworkType, routingResult *bpfRoutingResult) {
	if log.IsLevelEnabled(log.InfoLevel) {
		fields := log.Fields{
			"network": networkType.String(),
			"sniffed": domain,
			"ip":      RefineAddrPortToShow(dst),
			"pid":     routingResult.Pid,
			"ifindex": routingResult.Ifindex,
			"dscp":    routingResult.Dscp,
			"pname":   ProcessName2String(routingResult.Pname[:]),
			"mac":     Mac2String(routingResult.Mac[:]),
		}
		if consts.OutboundIndex(routingResult.Outbound) == consts.OutboundControlPlaneRouting {
			fields["controlPlaneRoute"] = "true"
		}
		networkTypeStr := strings.ToUpper(networkType.String())
		if dialOption.FallbackIpVersion {
			networkTypeStr = networkTypeStr + " (fallback)"
		}
		if dialOption.FallbackDialer {
			fields["originalOutbound"] = dialOption.Outbound.Name
			fields["originalPolicy"] = dialOption.Outbound.GetSelectionPolicy()
			fields["fallbackDialer"] = dialOption.Dialer.Name
			log.WithFields(fields).Infof("[%v] %v <-(fallback)-> %v", networkTypeStr, RefineSourceToShow(src, dst.Addr()), dialOption.DialTarget)
		} else {
			fields["outbound"] = dialOption.Outbound.Name
			fields["policy"] = dialOption.Outbound.GetSelectionPolicy()
			fields["dialer"] = dialOption.Dialer.Name
			log.WithFields(fields).Infof("[%v] %v <-> %v", networkTypeStr, RefineSourceToShow(src, dst.Addr()), dialOption.DialTarget)
		}
	}
}

func (c *ControlPlane) Route(src, dst netip.AddrPort, domain string, l4proto consts.L4ProtoType, routingResult *bpfRoutingResult) (outboundIndex consts.OutboundIndex, mark uint32, must bool, err error) {
	ipVersion := consts.IpVersionFromAddr(dst.Addr())
	bSrc := src.Addr().As16()
	bDst := dst.Addr().As16()
	var bMac [16]byte
	copy(bMac[10:], routingResult.Mac[:])
	return c.routingMatcher.Match(
		bSrc,
		bDst,
		src.Port(),
		dst.Port(),
		ipVersion,
		l4proto,
		domain,
		routingResult.Pname,
		routingResult.Ifindex,
		routingResult.Dscp,
		bMac,
	)
}

func (c *controlPlaneCore) RetrieveRoutingResult(src, dst netip.AddrPort, l4proto uint8) (result *bpfRoutingResult, err error) {
	srcIp6 := src.Addr().As16()
	dstIp6 := dst.Addr().As16()

	tuples := &bpfTuplesKey{
		Sip: struct {
			_       structs.HostLayout
			U6Addr8 [16]uint8
		}{U6Addr8: srcIp6},
		Sport: common.Htons(src.Port()),
		Dip: struct {
			_       structs.HostLayout
			U6Addr8 [16]uint8
		}{U6Addr8: dstIp6},
		Dport:   common.Htons(dst.Port()),
		L4proto: l4proto,
	}

	routingResult := c.routingResultPool.Get().(*bpfRoutingResult)
	if err := c.bpf.RoutingTuplesMap.Lookup(tuples, routingResult); err != nil {
		return nil, fmt.Errorf("reading map: key [%v, %v, %v]: %w", src.String(), l4proto, dst.String(), err)
	}
	return routingResult, nil
}

func (c *controlPlaneCore) RecycleRoutingResult(routingResult *bpfRoutingResult) {
	c.routingResultPool.Put(routingResult)
}

func RetrieveOriginalDest(oob []byte) netip.AddrPort {
	msgs, err := syscall.ParseSocketControlMessage(oob)
	if err != nil {
		return netip.AddrPort{}
	}
	for _, msg := range msgs {
		if msg.Header.Level == syscall.SOL_IP && msg.Header.Type == syscall.IP_RECVORIGDSTADDR {
			ip := msg.Data[4:8]
			port := binary.BigEndian.Uint16(msg.Data[2:4])
			return netip.AddrPortFrom(netip.AddrFrom4(*(*[4]byte)(ip)), port)
		} else if msg.Header.Level == syscall.SOL_IPV6 && msg.Header.Type == unix.IPV6_RECVORIGDSTADDR {
			ip := msg.Data[8:24]
			port := binary.BigEndian.Uint16(msg.Data[2:4])
			return netip.AddrPortFrom(netip.AddrFrom16(*(*[16]byte)(ip)), port)
		}
	}
	return netip.AddrPort{}
}

func checkIpforward(ifname string, ipversion consts.IpVersionStr) error {
	path := fmt.Sprintf("/proc/sys/net/ipv%v/conf/%v/forwarding", ipversion, ifname)
	b, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	if bytes.Equal(bytes.TrimSpace(b), []byte("1")) {
		return nil
	}
	return fmt.Errorf("ipforward on %v is off: %v; see docs of dae for help", ifname, path)
}

func CheckIpforward(ifname string) error {
	if err := checkIpforward(ifname, consts.IpVersionStr_4); err != nil {
		return err
	}
	if err := checkIpforward(ifname, consts.IpVersionStr_6); err != nil {
		return err
	}
	return nil
}

func setForwarding(ifname string, ipversion consts.IpVersionStr, val string) error {
	path := fmt.Sprintf("/proc/sys/net/ipv%v/conf/%v/forwarding", ipversion, ifname)
	err := os.WriteFile(path, []byte(val), 0644)
	if err != nil {
		return err
	}
	return nil
}

func SetIpv4forward(val string) error {
	err := os.WriteFile("/proc/sys/net/ipv4/ip_forward", []byte(val), 0644)
	if err != nil {
		return err
	}
	return nil
}

func SetForwarding(ifname string, val string) {
	_ = setForwarding(ifname, consts.IpVersionStr_4, val)
	_ = setForwarding(ifname, consts.IpVersionStr_6, val)
}

func checkSendRedirects(ifname string, ipversion consts.IpVersionStr) error {
	path := fmt.Sprintf("/proc/sys/net/ipv%v/conf/%v/send_redirects", ipversion, ifname)
	b, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	if bytes.Equal(bytes.TrimSpace(b), []byte("0")) {
		return nil
	}
	return fmt.Errorf("send_directs on %v is on: %v; see docs of dae for help", ifname, path)
}

func CheckSendRedirects(ifname string) error {
	if err := checkSendRedirects(ifname, consts.IpVersionStr_4); err != nil {
		return err
	}
	return nil
}

func setSendRedirects(ifname string, ipversion consts.IpVersionStr, val string) error {
	path := fmt.Sprintf("/proc/sys/net/ipv%v/conf/%v/send_redirects", ipversion, ifname)
	err := os.WriteFile(path, []byte(val), 0644)
	if err != nil {
		return err
	}
	return nil
}

func SetSendRedirects(ifname string, val string) {
	_ = setSendRedirects(ifname, consts.IpVersionStr_4, val)
}

func ProcessName2String(pname []uint8) string {
	return string(bytes.TrimRight(pname[:], string([]byte{0})))
}

func Mac2String(mac []uint8) string {
	ori := []byte(hex.EncodeToString(mac))
	// Insert ":".
	b := make([]byte, len(ori)/2*3-1)
	for i, j := 0, 0; i < len(ori); i, j = i+2, j+3 {
		copy(b[j:j+2], ori[i:i+2])
		if j+2 < len(b) {
			b[j+2] = ':'
		}
	}
	return string(b)
}

func IsPrivateIP(ip net.IP) bool {
	privateBlocks := []string{
		"10.0.0.0/8",
		"172.16.0.0/12",
		"192.168.0.0/16",
		"fc00::/7",  // IPv6 ULA
		"fe80::/10", // IPv6 link-local
	}
	for _, block := range privateBlocks {
		_, cidr, _ := net.ParseCIDR(block)
		if cidr.Contains(ip) {
			return true
		}
	}
	return false
}

func OutboundIndexByName(outbounds []*outbound.DialerGroup, name string) (consts.OutboundIndex, error) {
	for i, o := range outbounds {
		if o.Name == name {
			return consts.OutboundIndex(i), nil
		}
	}
	return consts.OutboundIndex(0xFF), oops.Errorf("outbound not found: %v", name)
}
