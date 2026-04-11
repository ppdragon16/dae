/*
*  SPDX-License-Identifier: AGPL-3.0-only
*  Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package common

import (
	"net/netip"
	"time"

	"github.com/daeuniverse/dae/common/consts"
)

func ShowDuration(d time.Duration) string {
	return d.Truncate(time.Millisecond).String()
}

func LatencyString(realLatency, latencyOffset time.Duration) string {
	var offsetSign string = "+"
	if latencyOffset < 0 {
		offsetSign = "-"
	}

	var offsetPart string = ""
	if latencyOffset != 0 {
		offsetPart = "(" + offsetSign + ShowDuration(latencyOffset.Abs()) + "=" + ShowDuration(realLatency+latencyOffset) + ")"
	}

	return ShowDuration(realLatency) + offsetPart
}

type NetworkType struct {
	L4Proto   consts.L4ProtoStr
	IpVersion consts.IpVersionStr
	str       string
}

func (t *NetworkType) String() string {
	return t.str
}

// 0: TCP4 DNS
// 1: TCP6 DNS
// 2: UDP4 DNS
// 3: UDP6 DNS
var allNetworkTypes = []*NetworkType{
	{L4Proto: consts.L4ProtoStr_TCP, IpVersion: consts.IpVersionStr_4, str: "tcp4"},
	{L4Proto: consts.L4ProtoStr_TCP, IpVersion: consts.IpVersionStr_6, str: "tcp6"},
	{L4Proto: consts.L4ProtoStr_UDP, IpVersion: consts.IpVersionStr_4, str: "udp4"},
	{L4Proto: consts.L4ProtoStr_UDP, IpVersion: consts.IpVersionStr_6, str: "udp6"},
}

var (
	NETWORK_TCP4 = allNetworkTypes[0]
	NETWORK_TCP6 = allNetworkTypes[1]
	NETWORK_UDP4 = allNetworkTypes[2]
	NETWORK_UDP6 = allNetworkTypes[3]
)

var unkIpNetworkTypes = []*NetworkType{
	{L4Proto: consts.L4ProtoStr_UDP, str: "udp"},
	{L4Proto: consts.L4ProtoStr_TCP, str: "tcp"},
}

func GetNetworkType(l4Proto consts.L4ProtoStr, addr netip.Addr) *NetworkType {
	switch {
	case addr.Is4() || addr.Is4In6():
		if l4Proto == consts.L4ProtoStr_UDP {
			return allNetworkTypes[2]
		}
		return allNetworkTypes[0]
	case addr.Is6():
		if l4Proto == consts.L4ProtoStr_UDP {
			return allNetworkTypes[3]
		}
		return allNetworkTypes[1]
	}
	if l4Proto == consts.L4ProtoStr_UDP {
		return unkIpNetworkTypes[0]
	}
	return unkIpNetworkTypes[1]
}

// networkTypeToIndex 将网络类型映射到集合索引
func NetworkTypeToIndex(typ *NetworkType) int {
	switch typ.L4Proto {
	case consts.L4ProtoStr_TCP:
		switch typ.IpVersion {
		case consts.IpVersionStr_4:
			return 0
		case consts.IpVersionStr_6:
			return 1
		}
	case consts.L4ProtoStr_UDP:
		// UDP share the DNS check result.
		switch typ.IpVersion {
		case consts.IpVersionStr_4:
			return 2
		case consts.IpVersionStr_6:
			return 3
		}
	}
	panic("invalid network type")
}

func IndexToNetworkType(index int) *NetworkType {
	if index < 0 || index > len(allNetworkTypes) {
		panic("invalid network type index")
	}
	return allNetworkTypes[index]
}
