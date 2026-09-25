/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package dialer

import (
	"fmt"
	"net/netip"
	"runtime"
	"syscall"

	"golang.org/x/sys/unix"
)

var fwmarkIoctl int

// TproxyTCPMaxSeg defines the maximum segment size clamped on the tproxy
// stream listener. Clamping prevents oversized segments when proxied traffic
// is later encapsulated in tunnel protocols: the client sizes its segments to
// the LAN MTU, but after proxy encapsulation each segment carries extra
// headers and may exceed the egress path MTU. Setting TproxyTCPMaxSeg <= 0
// disables MSS clamping on the listener. Note: on Linux TCP connections with
// timestamp options (12 bytes), setting TCP_MAXSEG to 1380 yields an
// effective payload MSS of ~1368 bytes in data segments.
var TproxyTCPMaxSeg = 1380

func init() {
	switch runtime.GOOS {
	case "linux", "android":
		fwmarkIoctl = 36 /* unix.SO_MARK */
	case "freebsd":
		fwmarkIoctl = 0x1015 /* unix.SO_USER_COOKIE */
	case "openbsd":
		fwmarkIoctl = 0x1021 /* unix.SO_RTABLE */
	}
}

func SoMarkControl(c syscall.RawConn, mark int) error {
	var sockOptErr error
	controlErr := c.Control(func(fd uintptr) {
		err := syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, fwmarkIoctl, mark)
		if err != nil {
			sockOptErr = fmt.Errorf("error setting SO_MARK socket option: %w", err)
		}
	})
	if controlErr != nil {
		return fmt.Errorf("error invoking socket control function: %w", controlErr)
	}
	return sockOptErr
}

func TproxyControl(c syscall.RawConn) error {
	var sockOptErr error
	controlErr := c.Control(func(fd uintptr) {
		// - https://www.kernel.org/doc/Documentation/networking/tproxy.txt
		if err := unix.SetsockoptInt(int(fd), unix.IPPROTO_IP, unix.IP_TRANSPARENT, 1); err != nil {
			sockOptErr = fmt.Errorf("error setting IP_TRANSPARENT socket option: %w", err)
			return
		}

		if err := unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_REUSEADDR, 1); err != nil {
			sockOptErr = fmt.Errorf("error setting SO_REUSEADDR socket option: %w", err)
			return
		}

		e4 := unix.SetsockoptInt(int(fd), syscall.SOL_IP, unix.IP_RECVORIGDSTADDR, 1)
		e6 := unix.SetsockoptInt(int(fd), syscall.SOL_IPV6, unix.IPV6_RECVORIGDSTADDR, 1)
		if e4 != nil && e6 != nil {
			if e4 != nil {
				sockOptErr = fmt.Errorf("error setting IP_RECVORIGDSTADDR socket option: %w", e4)
			} else {
				sockOptErr = fmt.Errorf("error setting IPV6_RECVORIGDSTADDR socket option: %w", e6)
			}
			return
		}

		// Check socket type: apply TCP-specific options only on stream
		// sockets (this control also serves the UDP listeners). Only on
		// Linux: the eBPF datapath was never supported on the BSD targets,
		// and unix.TCP_MAXSEG is not defined on all of their toolchains.
		//
		// Deliberately NO TCP_FASTOPEN here (RFC 7413): this transparent
		// proxy listener receives redirected SYNs whose Fast Open cookies
		// were minted for the real destination, so they would fail
		// validation and risk unconsented duplicate delivery of
		// non-idempotent request data. See kdae fce18b20.
		if runtime.GOOS != "linux" {
			return
		}
		if sockType, err := unix.GetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_TYPE); err == nil && sockType == unix.SOCK_STREAM {
			// Best-effort: a listener that refuses the clamp still works,
			// it just loses the oversize-segment protection.
			if TproxyTCPMaxSeg > 0 {
				_ = unix.SetsockoptInt(int(fd), unix.IPPROTO_TCP, unix.TCP_MAXSEG, TproxyTCPMaxSeg)
			}
		}
	})
	if controlErr != nil {
		return fmt.Errorf("error invoking socket control function: %w", controlErr)
	}
	return sockOptErr
}

func TransparentControl(c syscall.RawConn) error {
	var sockOptErr error
	controlErr := c.Control(func(fd uintptr) {
		if err := syscall.SetsockoptInt(int(fd), syscall.SOL_IP, syscall.IP_TRANSPARENT, 1); err != nil {
			sockOptErr = fmt.Errorf("error setting IP_TRANSPARENT socket option: %w", err)
		}
	})
	if controlErr != nil {
		return fmt.Errorf("error invoking socket control function: %w", controlErr)
	}
	return sockOptErr
}

func BindControl(c syscall.RawConn, lAddrPort netip.AddrPort) error {
	var sockOptErr error
	controlErr := c.Control(func(fd uintptr) {
		if err := syscall.SetsockoptInt(int(fd), syscall.SOL_IP, syscall.IP_TRANSPARENT, 1); err != nil {
			sockOptErr = fmt.Errorf("error setting IP_TRANSPARENT socket option: %w", err)
		}
		if err := bindAddr(fd, lAddrPort); err != nil {
			sockOptErr = fmt.Errorf("error bindAddr %v: %w", lAddrPort.String(), err)
		}
	})
	if controlErr != nil {
		return fmt.Errorf("error invoking socket control function: %w", controlErr)
	}
	return sockOptErr
}

func bindAddr(fd uintptr, addrPort netip.AddrPort) error {
	if err := syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_REUSEADDR, 1); err != nil {
		return fmt.Errorf("error setting SO_REUSEADDR socket option: %w", err)
	}

	if err := syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, unix.SO_REUSEPORT, 1); err != nil {
		return fmt.Errorf("error setting SO_REUSEPORT socket option: %w", err)
	}

	var sockAddr syscall.Sockaddr

	addr := addrPort.Addr()
	switch {
	case addr.Is4() || addr.Is4In6():
		a4 := &syscall.SockaddrInet4{
			Port: int(addrPort.Port()),
		}
		a4.Addr = addr.As4()
		sockAddr = a4
	case addr.Is6():
		a6 := &syscall.SockaddrInet6{
			Port: int(addrPort.Port()),
		}
		zone := addrPort.Addr().Zone()
		if zone != "" {
			//if link, e := netlink.LinkByName(zone); e == nil {
			//	a6.ZoneId = uint32(link.Attrs().Index)
			//}
			return fmt.Errorf("unsupported ipv6 zone")
		}
		a6.Addr = addr.As16()
		sockAddr = a6
	default:
		return fmt.Errorf("unexpected length of ip")
	}

	return syscall.Bind(int(fd), sockAddr)
}
