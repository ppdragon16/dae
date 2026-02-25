/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package netutils

import (
	"context"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"time"

	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/outbound/netproxy"
	"github.com/daeuniverse/outbound/pkg/fastrand"
	"github.com/daeuniverse/outbound/pool"
	dnsmessage "github.com/miekg/dns"
	"github.com/samber/oops"
)

var (
	ErrBadDnsAns  = fmt.Errorf("bad dns answer")
	ErrNoIpRecord = fmt.Errorf("no ip record found")
)

func ResolveHttp(client *http.Client, url *url.URL, data []byte) ([]byte, error) {
	// disable redirect https://github.com/daeuniverse/dae/pull/649#issuecomment-2379577896
	client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		return fmt.Errorf("do not use a server that will redirect, url: %v", url.String())
	}

	// According https://datatracker.ietf.org/doc/html/rfc8484#section-4
	// msg id should set to 0 when transport over HTTPS for cache friendly.
	binary.BigEndian.PutUint16(data[0:2], 0)

	q := url.Query()
	q.Set("dns", base64.RawURLEncoding.EncodeToString(data))
	url.RawQuery = q.Encode()

	req, err := http.NewRequest(http.MethodGet, url.String(), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/dns-message")
	req.Host = url.Host
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	buf, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	return buf, nil
}

func ResolveStream(stream io.ReadWriter, data []byte, quic bool) ([]byte, error) {
	if d, ok := stream.(interface{ SetDeadline(time.Time) error }); ok {
		d.SetDeadline(time.Now().Add(consts.DefaultDNSTimeout))
	}
	buf := pool.GetBytesBuffer()
	defer pool.PutBytesBuffer(buf)
	// We should write two byte length in the front of stream DNS request.
	binary.Write(buf, binary.BigEndian, uint16(len(data)))
	if quic {
		// According https://datatracker.ietf.org/doc/html/rfc9250#section-4.2.1
		// msg id should set to 0 when transport over QUIC.
		// thanks https://github.com/natesales/q/blob/1cb2639caf69bd0a9b46494a3c689130df8fb24a/transport/quic.go#L97
		buf.Write([]byte{0, 0})
		buf.Write(data[2:])
	} else {
		buf.Write(data)
	}
	_, err := stream.Write(buf.Bytes())
	if err != nil {
		return nil, oops.Wrapf(err, "failed to write DNS req")
	}

	lenBuf := pool.GetBuffer(2)
	defer pool.PutBuffer(lenBuf)
	// Read two byte length.
	if _, err = io.ReadFull(stream, lenBuf); err != nil {
		return nil, oops.Wrapf(err, "failed to read DNS resp payload length")
	}
	respBuf := make([]byte, binary.BigEndian.Uint16(lenBuf))
	if _, err = io.ReadFull(stream, respBuf); err != nil {
		return nil, oops.Wrapf(err, "failed to read DNS resp payload")
	}
	return respBuf, nil
}

func ResolveUDP(conn net.Conn, data []byte) (resp []byte, err error) {
	deadline := time.Now().Add(consts.DefaultDNSTimeout)
	conn.SetReadDeadline(deadline)

	ctx, cancel := context.WithDeadline(context.Background(), deadline)
	defer cancel()

	type result struct {
		data []byte
		err  error
	}

	recvCh := make(chan result, 1)

	go func() {
		// Wait for response.
		buf := make([]byte, consts.EthernetMtu)
		n, rErr := conn.Read(buf)
		select {
		case recvCh <- result{data: buf[:n], err: rErr}:
		case <-ctx.Done():
			return
		}
	}()

	ticker := time.NewTicker(consts.DefaultDNSRetryInterval)
	defer ticker.Stop()

	for i := 0; i < consts.DefaultDNSRetryCount; i++ {
		_, err = conn.Write(data)
		if err != nil {
			return nil, oops.Wrapf(err, "udp write error")
		}

		select {
		case res := <-recvCh:
			return res.data, res.err
		case <-ticker.C:
			continue
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}

	return nil, errors.New("dns lookup timeout")
}

func ResolveNetip(d netproxy.Dialer, dns netip.AddrPort, host string, typ uint16, network string) (addrs []netip.Addr, err error) {
	resources, err := resolve(d, dns, host, typ, network)
	if err != nil {
		return nil, err
	}
	for _, ans := range resources {
		if ans.Header().Rrtype != typ {
			continue
		}
		var (
			ip  netip.Addr
			okk bool
		)
		switch typ {
		case dnsmessage.TypeA:
			a, ok := ans.(*dnsmessage.A)
			if !ok {
				return nil, ErrBadDnsAns
			}
			ip, okk = netip.AddrFromSlice(a.A)
		case dnsmessage.TypeAAAA:
			a, ok := ans.(*dnsmessage.AAAA)
			if !ok {
				return nil, ErrBadDnsAns
			}
			ip, okk = netip.AddrFromSlice(a.AAAA)
		}
		if !okk {
			continue
		}
		addrs = append(addrs, ip)
	}
	return addrs, nil
}

func ResolveNS(d netproxy.Dialer, dns netip.AddrPort, host string, network string) (records []string, err error) {
	typ := dnsmessage.TypeNS
	resources, err := resolve(d, dns, host, typ, network)
	if err != nil {
		return nil, err
	}
	for _, ans := range resources {
		if ans.Header().Rrtype != typ {
			continue
		}
		ns, ok := ans.(*dnsmessage.NS)
		if !ok {
			return nil, ErrBadDnsAns
		}
		records = append(records, ns.Ns)
	}
	return records, nil
}

func ResolveSOA(d netproxy.Dialer, dns netip.AddrPort, host string, network string) (records []string, err error) {
	typ := dnsmessage.TypeSOA
	resources, err := resolve(d, dns, host, typ, network)
	if err != nil {
		return nil, err
	}
	for _, ans := range resources {
		if ans.Header().Rrtype != typ {
			continue
		}
		ns, ok := ans.(*dnsmessage.SOA)
		if !ok {
			return nil, ErrBadDnsAns
		}
		records = append(records, ns.Ns)
	}
	return records, nil
}

func DnsCheck(dialer netproxy.Dialer, dns netip.AddrPort, network string) (ok bool, err error) {
	resources, err := resolve(dialer, dns, consts.UdpCheckLookupHost, dnsmessage.TypeA, network)
	if err != nil {
		return false, err
	}
	for _, ans := range resources {
		if ans.Header().Rrtype == dnsmessage.TypeA {
			return true, nil
		}
	}
	return false, ErrNoIpRecord
}

func resolve(dialer netproxy.Dialer, server netip.AddrPort, host string, typ uint16, network string) (ans []dnsmessage.RR, err error) {
	// Build DNS req.
	msg := dnsmessage.Msg{
		MsgHdr: dnsmessage.MsgHdr{
			Id:               uint16(fastrand.Intn(math.MaxUint16 + 1)),
			Response:         false,
			Opcode:           0,
			Truncated:        false,
			RecursionDesired: true,
			Authoritative:    false,
		},
	}
	msg.SetQuestion(dnsmessage.CanonicalName(host), typ)

	ctx, cancel := context.WithTimeout(context.TODO(), consts.DefaultDialTimeout)
	defer cancel()
	conn, err := dialer.DialContext(ctx, network, server.String())
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	var data []byte
	if data, err = msg.Pack(); err == nil {
		var resp []byte
		if network == "tcp" {
			resp, err = ResolveStream(conn, data, false)
		} else {
			resp, err = ResolveUDP(conn, data)
		}
		if err == nil {
			err = msg.Unpack(resp)
		}
	}
	if err != nil {
		return nil, err
	}
	return msg.Answer, nil
}
