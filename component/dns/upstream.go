/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package dns

import (
	"context"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/daeuniverse/dae/common"
	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/common/netutils"
	"github.com/samber/oops"
)

var (
	ErrFormat = fmt.Errorf("format error")
)

type UpstreamScheme string

const (
	UpstreamScheme_TCP           UpstreamScheme = "tcp"
	UpstreamScheme_UDP           UpstreamScheme = "udp"
	UpstreamScheme_TCP_UDP       UpstreamScheme = "tcp+udp"
	upstreamScheme_TCP_UDP_Alias UpstreamScheme = "udp+tcp"
	UpstreamScheme_TLS           UpstreamScheme = "tls"
	UpstreamScheme_QUIC          UpstreamScheme = "quic"
	UpstreamScheme_HTTPS         UpstreamScheme = "https"
	upstreamScheme_H3_Alias      UpstreamScheme = "http3"
	UpstreamScheme_H3            UpstreamScheme = "h3"
)

func (s UpstreamScheme) ContainsTcp() bool {
	switch s {
	case UpstreamScheme_TCP,
		UpstreamScheme_TCP_UDP:
		return true
	default:
		return false
	}
}

func ParseRawUpstream(raw *url.URL) (scheme UpstreamScheme, hostname string, port uint16, path string, err error) {
	var __port string
	var __path string
	switch scheme = UpstreamScheme(raw.Scheme); scheme {
	case upstreamScheme_TCP_UDP_Alias:
		scheme = UpstreamScheme_TCP_UDP
		fallthrough
	case UpstreamScheme_TCP, UpstreamScheme_UDP, UpstreamScheme_TCP_UDP:
		__port = raw.Port()
		if __port == "" {
			__port = "53"
		}
	case upstreamScheme_H3_Alias:
		scheme = UpstreamScheme_H3
		fallthrough
	case UpstreamScheme_HTTPS, UpstreamScheme_H3:
		__port = raw.Port()
		if __port == "" {
			__port = "443"
		}
		__path = raw.Path
		if __path == "" {
			__path = "/dns-query"
		}
	case UpstreamScheme_QUIC, UpstreamScheme_TLS:
		__port = raw.Port()
		if __port == "" {
			__port = "853"
		}
	default:
		return "", "", 0, "", fmt.Errorf("unexpected scheme: %v", raw.Scheme)
	}
	_port, err := strconv.ParseUint(__port, 10, 16)
	if err != nil {
		return "", "", 0, "", fmt.Errorf("failed to parse dns_upstream port: %v", err)
	}
	port = uint16(_port)
	hostname = raw.Hostname()
	return scheme, hostname, port, __path, nil
}

type Upstream struct {
	Scheme   UpstreamScheme
	Hostname string
	Port     uint16
	Path     string
	*netutils.Ip46
	IsAsIs bool
}

// TODO: Sync with outbound
func NewUpstream(ctx context.Context, upstream *url.URL, resolverNetwork string) (up *Upstream, err error) {
	scheme, hostname, port, path, err := ParseRawUpstream(upstream)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrFormat, err)
	}

	ip46, err := netutils.ParseOrResolveIp46(hostname)
	if err != nil {
		return nil, oops.Wrapf(err, "failed to resolve dns_upstream %v", upstream.String())
	}
	if !ip46.IsValid() {
		return nil, oops.Errorf("dns_upstream %v has no record", upstream.String())
	}

	return &Upstream{
		Scheme:   scheme,
		Hostname: hostname,
		Port:     port,
		Path:     path,
		Ip46:     ip46,
	}, nil
}

func (u *Upstream) isUdpSupported() bool {
	return u.Scheme == UpstreamScheme_UDP || u.Scheme == UpstreamScheme_TCP_UDP || u.Scheme == UpstreamScheme_QUIC || u.Scheme == UpstreamScheme_H3
}

func (u *Upstream) isTcpSupported() bool {
	return u.Scheme == UpstreamScheme_TCP || u.Scheme == UpstreamScheme_TCP_UDP || u.Scheme == UpstreamScheme_HTTPS || u.Scheme == UpstreamScheme_TLS
}

func (u *Upstream) IsNetworkSupported(network *common.NetworkType) bool {
	if network.IpVersion == consts.IpVersionStr_6 && !u.Ip6.IsValid() {
		return false
	}
	if network.IpVersion == consts.IpVersionStr_4 && !u.Ip4.IsValid() {
		return false
	}
	if network.L4Proto == consts.L4ProtoStr_UDP && !u.isUdpSupported() {
		return false
	}
	if network.L4Proto == consts.L4ProtoStr_TCP && !u.isTcpSupported() {
		return false
	}
	return true
}

func (u *Upstream) String() string {
	return string(u.Scheme) + "://" + net.JoinHostPort(u.Hostname, strconv.Itoa(int(u.Port))) + u.Path
}

type UpstreamResolver struct {
	Raw     *url.URL
	Network string
	// FinishInitCallback may be invoked again if err is not nil
	FinishInitCallback func(raw *url.URL, upstream *Upstream)
	mu                 sync.Mutex
	upstream           *Upstream
	init               uint32
}

func (u *UpstreamResolver) GetUpstream() (_ *Upstream, err error) {
	if atomic.LoadUint32(&u.init) == 1 {
		return u.upstream, nil
	}

	u.mu.Lock()
	defer u.mu.Unlock()

	if u.init == 1 {
		return u.upstream, nil
	}

	ctx, cancel := context.WithTimeout(context.TODO(), 10*time.Second)
	defer cancel()
	upstream, err := NewUpstream(ctx, u.Raw, u.Network)
	if err != nil {
		return nil, fmt.Errorf("failed to init dns upstream: %w", err)
	}
	u.upstream = upstream
	u.FinishInitCallback(u.Raw, u.upstream)

	atomic.StoreUint32(&u.init, 1)
	return u.upstream, nil
}
