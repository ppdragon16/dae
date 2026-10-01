/*
*  SPDX-License-Identifier: AGPL-3.0-only
*  Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package consts

const (
	EthernetMtu = 1500

	// DnsMaxMessageSize is the largest DNS message on the wire: EDNS0
	// advertises the UDP payload size in a uint16 and DNS over TCP frames the
	// message with a two-byte length, so both transports share this ceiling.
	// Every read buffer that must hold a whole DNS message — parsed or
	// forwarded — sizes to it. Buffers that only probe liveness or carry a
	// query stay MTU-sized (EthernetMtu); see netutils.DnsCheck.
	DnsMaxMessageSize = 65535
)
