/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"encoding/binary"
	"net/netip"
	"time"

	"github.com/daeuniverse/dae/common"
	"github.com/daeuniverse/outbound/pool"
	dnsmessage "github.com/miekg/dns"
)

const (
	extendCacheDur = 1 * time.Hour
	minClientTtl   = 5
)

type DnsCache struct {
	Data       []byte
	TTLOffsets []int
	FetchedAt  time.Time
	IsNew      bool
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

func CopyResponseFromCache(cache *DnsCache) ([]byte, bool) {
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

type commonDnsCache[K comparable] struct {
	cache *common.TimeWheelCache[K, *DnsCache]
}

func newCommonDnsCache[K comparable]() *commonDnsCache[K] {
	return &commonDnsCache[K]{
		cache: common.NewTimeWheelCache[K, *DnsCache](extendCacheDur, 5*time.Second, func(key K, value *DnsCache) {
			common.DnsCacheSize.Dec()
		}),
	}
}

func (c *commonDnsCache[K]) Get(cacheKey K) *DnsCache {
	cache, ok := c.cache.Get(cacheKey)
	if !ok {
		return nil
	}
	if cache.IsNew {
		// Keep DnsCache instance as immutable, so make a copy and modify.
		copied := *cache
		copied.IsNew = false
		c.cache.Save(cacheKey, &copied)
		common.DnsCacheSize.Inc()
	}
	return cache
}

func (c *commonDnsCache[K]) UpdateAnswers(key K, data []byte, rrs []RRInfo, fixedTtl int) *DnsCache {
	if len(rrs) == 0 {
		return nil
	}
	var maxTTL uint32
	if fixedTtl > 0 {
		maxTTL = uint32(fixedTtl)
		for _, rr := range rrs {
			binary.BigEndian.PutUint32(data[rr.TTLOffset:rr.TTLOffset+4], maxTTL)
		}
	} else {
		for _, rr := range rrs {
			if rr.TTL > maxTTL {
				maxTTL = rr.TTL
			}
		}
	}
	if maxTTL < minClientTtl {
		return nil
	}

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
		IsNew:      true,
	}
	c.cache.Save(key, newCache)
	common.DnsCacheSize.Inc()
	return newCache
}

func (c *commonDnsCache[K]) Close() error {
	c.cache.Close()
	return nil
}
