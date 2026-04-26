/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package consts

import (
	"time"

	"golang.org/x/sys/unix"
)

type DialerSelectionPolicy string

const (
	DialerSelectionPolicy_Random                    DialerSelectionPolicy = "random"
	DialerSelectionPolicy_Fixed                     DialerSelectionPolicy = "fixed"
	DialerSelectionPolicy_MinAverage10Latencies     DialerSelectionPolicy = "min_avg10"
	DialerSelectionPolicy_MinMovingAverageLatencies DialerSelectionPolicy = "min_moving_avg"
	DialerSelectionPolicy_MinLastLatency            DialerSelectionPolicy = "min"
)

const (
	UdpCheckLookupHost = "connectivitycheck.gstatic.com."
	DefaultDialTimeout = 8 * time.Second
)

type L4ProtoStr string

const (
	L4ProtoStr_TCP L4ProtoStr = "tcp"
	L4ProtoStr_UDP L4ProtoStr = "udp"
)

func (l L4ProtoStr) ToL4Proto() uint8 {
	switch l {
	case L4ProtoStr_TCP:
		return unix.IPPROTO_TCP
	case L4ProtoStr_UDP:
		return unix.IPPROTO_UDP
	}
	panic("unsupported l4proto")
}

func (l L4ProtoStr) ToL4ProtoType() L4ProtoType {
	switch l {
	case L4ProtoStr_TCP:
		return L4ProtoType_TCP
	case L4ProtoStr_UDP:
		return L4ProtoType_UDP
	}
	panic("unsupported l4proto: " + l)
}

type IpVersionStr string

const (
	IpVersionStr_4 IpVersionStr = "4"
	IpVersionStr_6 IpVersionStr = "6"
)

func (v IpVersionStr) ToIpVersion() uint8 {
	switch v {
	case IpVersionStr_4:
		return 4
	case IpVersionStr_6:
		return 6
	}
	panic("unsupported ipversion")
}
