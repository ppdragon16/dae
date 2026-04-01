/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"encoding/binary"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"github.com/daeuniverse/dae/common"
	"github.com/daeuniverse/outbound/pool"
	dnsmessage "github.com/miekg/dns"
)

const (
	extendCacheDur = 1 * time.Hour
	minClientTtl   = 5
)

type dnsCache struct {
	Data       []byte
	TTLOffsets []uint16
	_offsets   [8]uint16
	FetchedAt  time.Time
	IsNew      int32
}

// Parse ips from DNS resp answers.
func GetIp(rr dnsmessage.RR) (netip.Addr, bool) {
	var (
		ip netip.Addr
		ok bool
	)
	switch body := rr.(type) {
	case *dnsmessage.A:
		ip, ok = netip.AddrFromSlice(body.A)
	case *dnsmessage.AAAA:
		ip, ok = netip.AddrFromSlice(body.AAAA)
	}
	if !ok || ip.IsUnspecified() {
		return ip, false
	}
	return ip, true
}

type commonDnsCache[K comparable] struct {
	cache *common.TimeWheelCache[K, *dnsCache]
	pool  *sync.Pool
}

func newCommonDnsCache[K comparable]() *commonDnsCache[K] {
	c := &commonDnsCache[K]{
		pool: &sync.Pool{
			New: func() any { return &dnsCache{} },
		},
	}
	c.cache = common.NewTimeWheelCache[K, *dnsCache](
		extendCacheDur, 5*time.Second, func(key K, value *dnsCache, replaced bool) {
			common.Metrics.DnsCacheSize.With0().Dec()
			value.Data = nil
			value.TTLOffsets = nil
			atomic.StoreInt32(&value.IsNew, 0)
			c.pool.Put(value)
		})
	return c
}

func (c *commonDnsCache[K]) Get(cacheKey K) (resp []byte, expired bool, isNew bool) {
	cache, ok := c.cache.Get(cacheKey)
	if !ok {
		return nil, false, false
	}
	resp, expired = copyResponseFromCache(cache)
	return resp, expired, atomic.CompareAndSwapInt32(&cache.IsNew, 1, 0)
}

func copyResponseFromCache(cache *dnsCache) ([]byte, bool) {
	respData := pool.GetBuffer(len(cache.Data))
	copy(respData, cache.Data)

	elapsed := uint32(uint32(time.Since(cache.FetchedAt).Seconds()))
	expired := false
	for _, offset := range cache.TTLOffsets {
		rawTtl := binary.BigEndian.Uint32(respData[offset : offset+4])
		clientTtl := uint32(0)
		if rawTtl > elapsed {
			clientTtl = rawTtl - elapsed
		}
		if clientTtl < minClientTtl {
			clientTtl = minClientTtl
			expired = true
		}
		binary.BigEndian.PutUint32(respData[offset:offset+4], clientTtl)
	}
	return respData, expired
}

func (c *commonDnsCache[K]) UpdateAnswers(key K, data []byte, fixedTtl int, isBackground bool) {
	it, ok := newDNSRRIterator(data)
	if !ok {
		return
	}
	lenRRs := it.remain
	if lenRRs == 0 {
		return
	}

	newCache := c.pool.Get().(*dnsCache)
	if lenRRs <= len(newCache._offsets) {
		newCache.TTLOffsets = newCache._offsets[:0]
	} else {
		newCache.TTLOffsets = make([]uint16, 0, lenRRs)
	}

	var maxTTL uint32
	if fixedTtl > 0 {
		maxTTL = uint32(fixedTtl)
		for off, ok := it.Next(); ok; off, ok = it.Next() {
			newCache.TTLOffsets = append(newCache.TTLOffsets, uint16(off+4))
			binary.BigEndian.PutUint32(data[off+4:off+8], maxTTL)
		}
	} else {
		for off, ok := it.Next(); ok; off, ok = it.Next() {
			newCache.TTLOffsets = append(newCache.TTLOffsets, uint16(off+4))
			ttl := binary.BigEndian.Uint32(data[off+4 : off+8])
			if ttl > maxTTL {
				maxTTL = ttl
			}
		}
	}
	if maxTTL < minClientTtl {
		newCache.TTLOffsets = nil
		c.pool.Put(newCache)
		return
	}

	if isBackground {
		newCache.Data = data
	} else {
		dataCopy := make([]byte, len(data))
		copy(dataCopy, data)
		newCache.Data = dataCopy
	}
	newCache.FetchedAt = time.Now()
	atomic.StoreInt32(&newCache.IsNew, 1)

	c.cache.Save(key, newCache)
	common.Metrics.DnsCacheSize.With0().Inc()
}

func (c *commonDnsCache[K]) Close() error {
	c.cache.Close()
	return nil
}
