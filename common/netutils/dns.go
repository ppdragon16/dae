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

	"github.com/daeuniverse/dae/common"
	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/outbound/netproxy"
	"github.com/daeuniverse/outbound/pkg/fastrand"
	"github.com/daeuniverse/outbound/pool"
	dnsmessage "github.com/miekg/dns"
)

const (
	resolveTcpTimeout       = 5 * time.Second
	resolveUdpRetryInterval = 2 * time.Second
	resolveUdpRetryCount    = 3
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

type deadlineStream interface {
	SetReadDeadline(time.Time) error
	SetWriteDeadline(time.Time) error
}

func ResolveStream(stream io.ReadWriter, data []byte, quic bool, respBuf []byte) ([]byte, error) {
	if d, ok := stream.(deadlineStream); ok {
		deadline := time.Now().Add(resolveTcpTimeout)
		d.SetReadDeadline(deadline)
		d.SetWriteDeadline(deadline)
	} else {
		return nil, errors.New("stream does not support deadlines")
	}

	buf := pool.GetBuffer(len(data) + 2)
	defer pool.PutBuffer(buf)
	// We should write two byte length in the front of stream DNS request.
	binary.BigEndian.PutUint16(buf, uint16(len(data)))
	if quic {
		// According https://datatracker.ietf.org/doc/html/rfc9250#section-4.2.1
		// msg id should set to 0 when transport over QUIC.
		// thanks https://github.com/natesales/q/blob/1cb2639caf69bd0a9b46494a3c689130df8fb24a/transport/quic.go#L97
		buf[2] = 0
		buf[3] = 0
		copy(buf[4:], data[2:])
	} else {
		copy(buf[2:], data)
	}
	_, err := stream.Write(buf)
	if err != nil {
		return nil, err
	}
	return readResolveStream(stream, buf[:2], respBuf)
}

func readResolveStream(stream io.ReadWriter, lenBuf []byte, respBuf []byte) (resp []byte, err error) {
	// Read two byte length.
	if _, err = io.ReadFull(stream, lenBuf[:2]); err != nil {
		err = common.Wrap(err, "failed to read DNS resp payload length")
	}
	var n int
	if err == nil {
		respLen := binary.BigEndian.Uint16(lenBuf[:2])
		if int(respLen) > len(respBuf) {
			err = fmt.Errorf("DNS resp payload is too large")
		} else if n, err = io.ReadFull(stream, respBuf[:respLen]); err != nil {
			err = common.Wrap(err, "failed to read DNS resp payload")
		}
	}
	if err == nil {
		return respBuf[:n], nil
	}
	return nil, err
}

func ResolveUDP(conn net.Conn, data []byte, respBuf []byte) (resp []byte, err error) {
	deadline := time.Now().Add(resolveUdpRetryInterval * resolveUdpRetryCount)
	conn.SetReadDeadline(deadline)

	ctx, cancel := context.WithDeadline(context.Background(), deadline)
	defer cancel()

	recvCh := make(chan error, 1)
	var n int
	go func() {
		// Wait for response.
		var rErr error
		n, rErr = conn.Read(respBuf)
		recvCh <- rErr
	}()

	ticker := time.NewTicker(resolveUdpRetryInterval)
	defer ticker.Stop()

	for i := 0; i < resolveUdpRetryCount; i++ {
		_, err = conn.Write(data)
		if err != nil {
			return nil, common.Wrap(err, "udp write error")
		}

		select {
		case err = <-recvCh:
			if err == nil {
				return respBuf[:n], nil
			}
			return nil, err
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

func DnsCheck(dialer netproxy.Dialer, server string, network string, data []byte) (bool, error) {
	resp := pool.GetBuffer(consts.EthernetMtu)
	defer pool.PutBuffer(resp)
	_, err := resolveMsg(dialer, server, network, data, resp)
	return err == nil, err
}

func resolveMsg(dialer netproxy.Dialer, server string, network string, data []byte, respBuf []byte) (resp []byte, err error) {
	ctx, cancel := context.WithTimeout(context.TODO(), consts.DefaultDialTimeout)
	defer cancel()
	conn, err := dialer.DialContext(ctx, network, server)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	if network == "tcp" {
		return ResolveStream(conn, data, false, respBuf)
	}
	return ResolveUDP(conn, data, respBuf)
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
	msg.SetQuestion(common.CanonicalName(host), typ)

	data := pool.GetBuffer(consts.EthernetMtu)
	defer pool.PutBuffer(data)
	if data, err = msg.PackBuffer(data); err != nil {
		return nil, err
	}

	respBuf := pool.GetBuffer(consts.EthernetMtu)
	defer pool.PutBuffer(respBuf)
	resp, err := resolveMsg(dialer, server.String(), network, data, respBuf)
	if err != nil {
		return nil, err
	}
	msg = dnsmessage.Msg{}
	if err = msg.Unpack(resp); err != nil {
		return nil, err
	}
	return msg.Answer, nil

}
