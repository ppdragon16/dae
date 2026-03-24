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
	"strconv"
	"strings"
	"structs"
	"sync"
	"syscall"

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

var dialOptionPool = sync.Pool{New: func() any { return &DialOption{} }}

func ObtainDialOption() *DialOption {
	v := dialOptionPool.Get()
	return v.(*DialOption)
}

func RecycleDialOption(option *DialOption) {
	dialOptionPool.Put(option)
}

func IsNetError(err error) (netErr net.Error, ok bool) {
	ok = errors.As(err, &netErr)
	return
}

func (c *ControlPlane) RouteDialOption(
	src, dst netip.AddrPort,
	domain string,
	networkType *common.NetworkType,
	routingResult *bpfRoutingResult,
	dialOptionOut *DialOption) (err error) {
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
	dialTarget, dialIp := chooseDialTarget(dst, domain, verified && c.dialTargetOverride)
	dialer, fallback, err := outbound.SelectFallbackIpVersion(networkType, dialIp)
	fallbackDialer := false
	if err != nil {
		dialer, err = c.outbounds[c.noConnectivityOutbound].Select(networkType)
		if err != nil {
			panic(fmt.Sprintf("fail to get fallback dialer %v(%v): %v", c.outbounds[c.noConnectivityOutbound], c.noConnectivityOutbound, err))
		}
		fallbackDialer = true
	}
	dialOptionOut.DialTarget = dialTarget
	dialOptionOut.Dialer = dialer
	dialOptionOut.Outbound = outbound
	dialOptionOut.FallbackIpVersion = fallback
	dialOptionOut.FallbackDialer = fallbackDialer
	return nil
}

func chooseDialTarget(dst netip.AddrPort, domain string, override bool) (dialTarget string, dialIp bool) {
	if !override || len(domain) == 0 {
		return dst.String(), true
	}
	// domain cases:
	// - ""
	// - "abc.xyz.com"
	// - "abc.xyz.com:789"
	// - "[2606:4700:20::681a:d1f]"
	// - "2606:4700:20::681a:d1f"
	// - "111.222.333.444"
	// - "[2606:4700:20::681a:d1f]:5678"
	// - "111.222.333.444:5678"
	hasAlpha := false
	lastColon := -1
	colonCount := 0
	inBracket := domain[0] == '['
	for i := range len(domain) {
		c := domain[i]
		if !hasAlpha && ((c >= 'g' && c <= 'z') || (c >= 'G' && c <= 'Z')) {
			hasAlpha = true
		}
		if inBracket && c == ']' {
			inBracket = false
		}
		if !inBracket && c == ':' {
			lastColon = i
			colonCount++
		}
	}

	if lastColon > 0 {
		// domain-or-ip4/6:port
		dialTarget = domain
	} else if colonCount > 1 {
		// ipv6 address
		dialTarget = "[" + domain + "]:" + strconv.Itoa(int(dst.Port()))
		dialIp = true
	} else {
		// ipv4 address or domain
		dialTarget = domain + ":" + strconv.Itoa(int(dst.Port()))
		if !hasAlpha {
			// ipv4 address
			dialIp = true
		}
	}

	if log.IsLevelEnabled(log.DebugLevel) {
		log.WithFields(log.Fields{
			"from": dst.String(),
			"to":   dialTarget,
		}).Debugln("Rewrite dial target to domain")
	}
	return
}

type TrafficLogConn struct {
	net.Conn
	onTraffic func(dir string, n int64)
	counter   prometheus.Counter
}

func NewTrafficLogConn(conn net.Conn, counter prometheus.Counter, onTraffic func(dir string, n int64)) *TrafficLogConn {
	return &TrafficLogConn{
		onTraffic: onTraffic,
		Conn:      conn,
		counter:   counter,
	}
}

func (tc *TrafficLogConn) Read(p []byte) (int, error) {
	n, err := tc.Conn.Read(p)
	tc.counter.Add(float64(n))
	if tc.onTraffic != nil {
		tc.onTraffic("down", int64(n))
	}
	return n, err
}

func (tc *TrafficLogConn) Write(p []byte) (int, error) {
	n, err := tc.Conn.Write(p)
	tc.counter.Add(float64(n))
	if tc.onTraffic != nil {
		tc.onTraffic("up", int64(n))
	}
	return n, err
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

func (c *controlPlaneCore) RetrieveTCPRoutingResult(src, dst netip.AddrPort, outResult *bpfRoutingResult) error {
	tuples := &bpfTuplesKey{
		Sip: struct {
			_       structs.HostLayout
			U6Addr8 [16]uint8
		}{U6Addr8: src.Addr().As16()},
		Sport: common.Htons(src.Port()),
		Dip: struct {
			_       structs.HostLayout
			U6Addr8 [16]uint8
		}{U6Addr8: dst.Addr().As16()},
		Dport:   common.Htons(dst.Port()),
		L4proto: unix.IPPROTO_TCP,
	}

	if err := c.bpf.RoutingTuplesMap.Lookup(tuples, outResult); err != nil {
		return fmt.Errorf("reading map for tcp: key [%v, tcp, %v]: %w", src.String(), dst.String(), err)
	}
	return nil
}

func (c *controlPlaneCore) RetrieveUDPRoutingResult(src netip.AddrPort, outResult *bpfRoutingResult) error {
	tuples := &bpfTuplesKey{
		Sip: struct {
			_       structs.HostLayout
			U6Addr8 [16]uint8
		}{U6Addr8: src.Addr().As16()},
		Sport:   common.Htons(src.Port()),
		L4proto: unix.IPPROTO_UDP,
	}

	if err := c.bpf.RoutingTuplesMap.Lookup(tuples, outResult); err != nil {
		return fmt.Errorf("reading map for udp: key [%v, udp, 0]: %w", src.String(), err)
	}
	return nil
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
