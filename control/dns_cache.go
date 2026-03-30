/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"net/netip"
	"time"

	"github.com/daeuniverse/dae/common"
	dnsmessage "github.com/miekg/dns"
)

const (
	extendCacheDur = 1 * time.Hour
	minClientTtl   = 5
)

type DnsCache struct {
	Answers   []dnsmessage.RR
	FetchedAt time.Time
	IsNew     bool
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

func FillMsgByCache(msg *dnsmessage.Msg, cache *DnsCache) (originalMsgForExpiredFetch *dnsmessage.Msg) {
	// Ugly copying RR logic to avoid concurrent read/write TTL.
	// TODO: Optimize this by byte-level copying?
	m := &dnsmessage.Msg{}
	ttls := make([]uint32, 0)
	ttlDeduction := uint32(time.Since(cache.FetchedAt).Seconds())
	for _, ans := range cache.Answers {
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

func (c *commonDnsCache[K]) UpdateAnswers(key K, answers []dnsmessage.RR, fixedTtl int) *DnsCache {
	if len(answers) == 0 {
		return nil
	}

	var maxTTL uint32
	if fixedTtl > 0 {
		maxTTL = uint32(fixedTtl)
		for _, ans := range answers {
			ans.Header().Ttl = uint32(fixedTtl)
		}
	} else {
		for _, ans := range answers {
			if ttl := ans.Header().Ttl; ttl > maxTTL {
				maxTTL = ttl
			}
		}
	}
	if maxTTL < minClientTtl {
		return nil
	}
	newCache := &DnsCache{
		Answers:   answers,
		FetchedAt: time.Now(),
		IsNew:     true,
	}

	c.cache.Save(key, newCache)
	common.DnsCacheSize.Inc()
	return newCache
}

func (c *commonDnsCache[K]) Close() error {
	c.cache.Close()
	return nil
}
