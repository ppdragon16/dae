package control

import "net/netip"

type AddrPortPair struct {
	Src netip.AddrPort
	Dst netip.AddrPort
}

// Used as hash func for common.ShardedKeyLocker.
func AddrPortPairShard(key AddrPortPair, mask uint32) uint32 {
	const (
		offset32 = 2166136261
		prime32  = 16777619
	)
	src := key.Src
	dst := key.Dst

	h := uint32(offset32)

	h = hashAddr(h, src.Addr(), prime32)
	p1 := src.Port()
	h = (h ^ uint32(uint8(p1))) * prime32
	h = (h ^ uint32(uint8(p1>>8))) * prime32

	h = hashAddr(h, dst.Addr(), prime32)
	p2 := dst.Port()
	h = (h ^ uint32(uint8(p2))) * prime32
	h = (h ^ uint32(uint8(p2>>8))) * prime32

	return h & mask
}

func hashAddr(h uint32, addr netip.Addr, prime uint32) uint32 {
	if addr.Is4() {
		a4 := addr.As4()
		h = (h ^ uint32(a4[0])) * prime
		h = (h ^ uint32(a4[1])) * prime
		h = (h ^ uint32(a4[2])) * prime
		h = (h ^ uint32(a4[3])) * prime
	} else {
		a16 := addr.As16()
		for i := 0; i < 16; i++ {
			h = (h ^ uint32(a16[i])) * prime
		}
	}
	return h
}
