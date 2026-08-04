/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"fmt"
	"strconv"
	"strings"

	dnsmessage "github.com/miekg/dns"
)

// dnsDefaultUDPSize is the classic DNS-over-UDP response size limit
// (RFC 1035 section 4.2.1). Responses exceeding this limit must be
// truncated with the TC bit set so the client retries over TCP.
const dnsDefaultUDPSize = 512

type RscWrapper struct {
	Rsc dnsmessage.RR
}

func (w RscWrapper) String() string {
	var strBody string
	switch body := w.Rsc.(type) {
	case *dnsmessage.A:
		strBody = body.A.String()
	case *dnsmessage.AAAA:
		strBody = body.AAAA.String()
	case *dnsmessage.CNAME:
		strBody = body.Target
	default:
		strBody = body.String()
	}
	return fmt.Sprintf("%v(%v): %v", w.Rsc.Header().Name, QtypeToString(w.Rsc.Header().Rrtype), strBody)
}

func FormatDnsRsc(ans []dnsmessage.RR) string {
	var w []string
	for _, a := range ans {
		w = append(w, RscWrapper{Rsc: a}.String())
	}
	return strings.Join(w, "; ")
}

func QtypeToString(qtype uint16) string {
	str, ok := dnsmessage.TypeToString[qtype]
	if !ok {
		str = strconv.Itoa(int(qtype))
	}
	return str
}
