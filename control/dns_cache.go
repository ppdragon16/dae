/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"net/netip"
	"sync/atomic"
	"time"

	"github.com/daeuniverse/dae/common"
	dnsmessage "github.com/miekg/dns"
)

const (
	extendCacheDur = 1 * time.Hour
	minClientTtl   = 5
	minSaveTtl     = 15
)

// 64位哈希，理论冲突概率为 1/2^64，不绝对安全但是够用
type HashKey uint64

type dnsCache struct {
	Answers   []dnsmessage.RR
	FetchedAt time.Time
	IsNew     int32
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

func FillMsgByCache(msg *dnsmessage.Msg, rr []dnsmessage.RR, fetchedAt time.Time) (originalMsgForExpiredFetch *dnsmessage.Msg) {
	// Ugly copying RR logic to avoid concurrent read/write TTL.
	// TODO: Optimize this by byte-level copying?
	m := &dnsmessage.Msg{}
	ttls := make([]uint32, 0)
	ttlDeduction := uint32(time.Since(fetchedAt).Seconds())
	for _, ans := range rr {
		rawTtl := ans.Header().Ttl
		clientTtl := uint32(0)
		if rawTtl > ttlDeduction {
			clientTtl = rawTtl - ttlDeduction
		}
		if clientTtl < minClientTtl {
			clientTtl = minClientTtl
			if originalMsgForExpiredFetch == nil {
				originalMsgForExpiredFetch = msg.Copy()
			}
		}
		ttls = append(ttls, clientTtl)
		m.Answer = append(m.Answer, ans)
	}
	m = m.Copy()
	for i := range m.Answer {
		m.Answer[i].Header().Ttl = ttls[i]
	}
	msg.Answer = m.Answer
	msg.Rcode = dnsmessage.RcodeSuccess
	msg.Response = true
	msg.RecursionAvailable = true
	msg.Truncated = false
	return
}

func IncludeAnyIpInMsg(msg *dnsmessage.Msg) bool {
	for _, ans := range msg.Answer {
		switch ans.(type) {
		case *dnsmessage.A, *dnsmessage.AAAA:
			return true
		}
	}
	return false
}

type commonDnsCache struct {
	cache *common.TimeWheelCache[HashKey, *dnsCache]
}

func newCommonDnsCache() *commonDnsCache {
	c := &commonDnsCache{}
	c.cache = common.NewTimeWheelCache[HashKey, *dnsCache](
		extendCacheDur, 5*time.Second, func(key HashKey, value *dnsCache, replaced bool) {
			common.Metrics.DnsCacheSize.With0().Dec()
			atomic.StoreInt32(&value.IsNew, 0)
		})
	return c
}

func (c *commonDnsCache) Get(cacheKey HashKey) (rr []dnsmessage.RR, fetchedAt time.Time, isNew bool) {
	cache, ok := c.cache.Get(cacheKey)
	if !ok {
		return nil, time.Time{}, false
	}
	return cache.Answers, cache.FetchedAt, atomic.CompareAndSwapInt32(&cache.IsNew, 1, 0)
}

// Range iterates over every cached DNS response. See common.TimeWheelCache.Range.
func (c *commonDnsCache) Range(fn func(key HashKey, value *dnsCache, ttl time.Duration) bool) {
	c.cache.Range(fn)
}

func (c *commonDnsCache) Save(key HashKey, answers []dnsmessage.RR, fixedTtl int) {
	if len(answers) == 0 {
		return
	}

	var maxTTL uint32
	if fixedTtl > 0 {
		maxTTL = uint32(fixedTtl)
		for _, ans := range answers {
			ans.Header().Ttl = uint32(fixedTtl)
		}
	} else {
		for _, ans := range answers {
			rtype := ans.Header().Rrtype
			if rtype != dnsmessage.TypeA && rtype != dnsmessage.TypeAAAA {
				continue
			}
			if ttl := ans.Header().Ttl; ttl > maxTTL {
				maxTTL = ttl
			}
		}
	}
	if maxTTL < minSaveTtl {
		return
	}
	newCache := &dnsCache{
		Answers:   answers,
		FetchedAt: time.Now(),
		IsNew:     1,
	}

	c.cache.Save(key, newCache)
	common.Metrics.DnsCacheSize.With0().Inc()
}

func (c *commonDnsCache) Close() error {
	c.cache.Close()
	return nil
}
