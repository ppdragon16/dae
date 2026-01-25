/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"encoding/binary"
	"net/netip"
	"sync"
	"time"

	"github.com/daeuniverse/dae/common"
	"github.com/daeuniverse/outbound/pool"
	dnsmessage "github.com/miekg/dns"
)

type DnsCache struct {
	Data       []byte
	TTLOffsets []int
	FetchedAt  time.Time
	timer      *time.Timer
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

func CopyResponseFromCache(cache *DnsCache) []byte {
	now := time.Now()

	respData := pool.GetBuffer(len(cache.Data))
	copy(respData, cache.Data)

	elapsed := uint32(now.Sub(cache.FetchedAt).Seconds())

	hasValidTtl := false
	for _, offset := range cache.TTLOffsets {
		ttl := binary.BigEndian.Uint32(respData[offset : offset+4])
		if ttl > elapsed {
			ttl -= elapsed
			hasValidTtl = true
		} else {
			ttl = 0 // Client gets min TTL = 0
		}
		binary.BigEndian.PutUint32(respData[offset:offset+4], ttl)
	}

	if !hasValidTtl {
		pool.PutBuffer(respData)
		return nil
	}
	return respData
}

type commonDnsCache[K comparable] struct {
	cache map[K]*DnsCache
	mu    sync.RWMutex
}

func newCommonDnsCache[K comparable]() *commonDnsCache[K] {
	return &commonDnsCache[K]{
		cache: make(map[K]*DnsCache),
	}
}

func (c *commonDnsCache[K]) Get(cacheKey K) *DnsCache {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if dnsCache, ok := c.cache[cacheKey]; ok {
		return dnsCache
	}
	return nil
}

func (c *commonDnsCache[K]) UpdateTtl(key K, data []byte, rrs []RRInfo, ttl uint32) *DnsCache {
	c.mu.Lock()
	defer c.mu.Unlock()

	ttlOffsets := make([]int, len(rrs))
	for i, info := range rrs {
		ttlOffsets[i] = info.TTLOffset
	}

	dataCopy := make([]byte, len(data))
	copy(dataCopy, data)

	newCache := &DnsCache{
		Data:       dataCopy,
		TTLOffsets: ttlOffsets,
		FetchedAt:  time.Now(),
	}
	newCache.timer = time.AfterFunc(time.Duration(ttl)*time.Second, func() {
		c.mu.Lock()
		defer c.mu.Unlock()
		if cache, ok := c.cache[key]; ok {
			if cache == newCache {
				common.DnsCacheSize.Dec()
				delete(c.cache, key)
			}
		}
	})

	if existingCache, ok := c.cache[key]; ok {
		existingCache.timer.Stop()
	} else {
		common.DnsCacheSize.Inc()
	}
	c.cache[key] = newCache

	return newCache
}
