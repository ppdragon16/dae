/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"encoding/binary"
	"sync"
	"sync/atomic"
	"time"

	"github.com/daeuniverse/dae/common"
	"github.com/daeuniverse/outbound/pool"
)

const (
	extendCacheDur = 1 * time.Hour
	minClientTtl   = 5
	minSaveTtl     = 15
)

// 64位哈希，理论冲突概率为 1/2^64，不绝对安全但是够用
type HashKey uint64

type dnsCache struct {
	Data       []byte
	TTLOffsets []uint16
	_offsets   [8]uint16
	FetchedAt  time.Time
	IsNew      int32
}

type commonDnsCache struct {
	cache *common.TimeWheelCache[HashKey, *dnsCache]
	pool  *sync.Pool
}

func NewCommonDnsCache() *commonDnsCache {
	c := &commonDnsCache{
		pool: &sync.Pool{
			New: func() any { return &dnsCache{} },
		},
	}
	c.cache = common.NewTimeWheelCache[HashKey, *dnsCache](
		extendCacheDur, 5*time.Second, func(key HashKey, value *dnsCache, replaced bool) {
			common.Metrics.DnsCacheSize.With0().Dec()
			value.Data = nil
			value.TTLOffsets = nil
			atomic.StoreInt32(&value.IsNew, 0)
			c.pool.Put(value)
		})
	return c
}

func (c *commonDnsCache) Get(key HashKey) (resp []byte, expired bool, isNew bool) {
	cache, ok := c.cache.Get(key)
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

func (c *commonDnsCache) NewCache(data []byte, fixedTtl int, directSave bool) *dnsCache {
	it, ok := newDNSRRIterator(data)
	if !ok {
		return nil
	}
	lenRRs := it.remain
	if lenRRs == 0 {
		return nil
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
			rtype := binary.BigEndian.Uint16(it.data[off : off+2])
			if rtype != 1 && rtype != 28 {
				continue
			}
			ttl := binary.BigEndian.Uint32(data[off+4 : off+8])
			if ttl > maxTTL {
				maxTTL = ttl
			}
		}
	}
	if maxTTL < minSaveTtl {
		newCache.TTLOffsets = nil
		c.pool.Put(newCache)
		return nil
	}

	if directSave {
		newCache.Data = data
	} else {
		dataCopy := make([]byte, len(data))
		copy(dataCopy, data)
		newCache.Data = dataCopy
	}
	newCache.FetchedAt = time.Now()
	atomic.StoreInt32(&newCache.IsNew, 1)
	return newCache
}

func (c *commonDnsCache) Save(key HashKey, newCache *dnsCache) {
	c.cache.Save(key, newCache)
	common.Metrics.DnsCacheSize.With0().Inc()
}

func (c *commonDnsCache) Close() error {
	c.cache.Close()
	return nil
}
