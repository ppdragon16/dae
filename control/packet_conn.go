package control

import "net/netip"

type PacketConnAddrPort interface {
	ReadFromAddrPort(b []byte) (n int, addr netip.AddrPort, err error)
	WriteToAddrPort(b []byte, ap netip.AddrPort) (int, error)
}
