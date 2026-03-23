package common

import (
	"unsafe"

	"github.com/daeuniverse/outbound/pool"
)

func ObtainDomainBitmap() []uint32 {
	buf := pool.GetBuffer(128)
	return unsafe.Slice((*uint32)(unsafe.Pointer(&buf[0])), 32)
}

func RecycleDomainBitmap(bitmap []uint32) {
	if bitmap == nil || cap(bitmap) == 0 {
		return
	}
	pool.PutBuffer(unsafe.Slice((*byte)(unsafe.Pointer(&bitmap[0])), 128))
}
