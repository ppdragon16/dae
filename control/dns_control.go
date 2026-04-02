/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"encoding/binary"
	"fmt"
	"hash/crc32"
	"hash/maphash"
	"io"
	"math"
	"net/netip"
	"strings"
	"sync"
	"time"
	"unsafe"

	"github.com/daeuniverse/dae/common"
	"github.com/daeuniverse/dae/common/netutils"

	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/component/dns"
	"github.com/daeuniverse/dae/component/outbound"
	"github.com/daeuniverse/dae/component/outbound/dialer"
	"github.com/daeuniverse/dae/config"
	"github.com/daeuniverse/outbound/pkg/fastrand"
	"github.com/daeuniverse/outbound/pool"
	dnsmessage "github.com/miekg/dns"
	log "github.com/sirupsen/logrus"
)

// TODO: Lookup Cache 的 GC
// TODO: reload时保留lookup cache

const (
	MaxDnsLookupDepth = 3
)

type IpVersionPrefer int

const (
	IpVersionPrefer_No IpVersionPrefer = 0
	IpVersionPrefer_4  IpVersionPrefer = 4
	IpVersionPrefer_6  IpVersionPrefer = 6
)

var (
	UnspecifiedAddressA        = netip.MustParseAddr("0.0.0.0")
	UnspecifiedAddressAAAA     = netip.MustParseAddr("::")
	ErrUnsupportedQuestionType = fmt.Errorf("unsupported question type")
)

type DnsControllerOption struct {
	MatchBitmap        func(fqdn string, bitmap []uint32)
	NewLookupCache     func(ip netip.Addr, domainBitmap *[32]uint32) error
	LookupCacheTimeout func(ip netip.Addr, domainBitmap *[32]uint32) error
	BestDialerChooser  func(req *dnsRequest, upstream *dns.Upstream, outArg *dialArgument) error
	IpVersionPrefer    int
	FixedDomainTtl     map[string]int
	MinSniffingTtl     time.Duration
	EnableCache        bool
	SniffVerifyMode    consts.SniffVerifyMode
}

type coreIpDomainCacheValue struct {
	qname  string
	ip     netip.Addr
	bitmap *[32]uint32
}

type DnsController struct {
	routing     *dns.Dns
	qtypePrefer uint16

	matchBitmap        func(fqdn string, bitmap []uint32)
	newLookupCache     func(ip netip.Addr, domainBitmap *[32]uint32) error
	lookupCacheTimeout func(ip netip.Addr, domainBitmap *[32]uint32) error
	bestDialerChooser  func(req *dnsRequest, upstream *dns.Upstream, outArg *dialArgument) error

	fixedDomainTtl     map[string]int
	minSniffingTtl     time.Duration
	enableCache        bool
	dnsCache           *commonDnsCache
	dnsCacheHashSeed   maphash.Seed
	dnsForwarderCache  sync.Map // map[dnsForwarderKey]DnsForwarder
	requestSelectCache *common.TimeWheelCache[HashKey, consts.DnsRequestOutboundIndex]
	// mu protects lookupCache
	mu                sync.Mutex
	lookupCache       map[string]map[netip.Addr]uint32
	coreIpDomainCache *common.TimeWheelCache[uint32, coreIpDomainCacheValue]
	sniffVerifyMode   consts.SniffVerifyMode

	singleFlightGroup common.SingleFlight[dnsCacheKey, []byte, singleFlightParam]
}

func parseIpVersionPreference(prefer int) (uint16, error) {
	switch prefer := IpVersionPrefer(prefer); prefer {
	case IpVersionPrefer_No:
		return 0, nil
	case IpVersionPrefer_4:
		return dnsmessage.TypeA, nil
	case IpVersionPrefer_6:
		return dnsmessage.TypeAAAA, nil
	default:
		return 0, fmt.Errorf("unknown preference: %v", prefer)
	}
}

func NewDnsController(routing *dns.Dns, option *DnsControllerOption) (c *DnsController, err error) {
	// Parse ip version preference.
	prefer, err := parseIpVersionPreference(option.IpVersionPrefer)
	if err != nil {
		return nil, err
	}

	c = &DnsController{
		routing:     routing,
		qtypePrefer: prefer,

		matchBitmap:        option.MatchBitmap,
		newLookupCache:     option.NewLookupCache,
		lookupCacheTimeout: option.LookupCacheTimeout,
		bestDialerChooser:  option.BestDialerChooser,

		fixedDomainTtl:     option.FixedDomainTtl,
		minSniffingTtl:     option.MinSniffingTtl,
		enableCache:        option.EnableCache,
		sniffVerifyMode:    option.SniffVerifyMode,
		dnsForwarderCache:  sync.Map{},
		dnsCache:           NewCommonDnsCache(),
		dnsCacheHashSeed:   maphash.MakeSeed(),
		requestSelectCache: common.NewTimeWheelCache[HashKey, consts.DnsRequestOutboundIndex](1*time.Hour, 5*time.Second, nil),
		lookupCache:        make(map[string]map[netip.Addr]uint32),
	}
	c.coreIpDomainCache = common.NewTimeWheelCache[uint32, coreIpDomainCacheValue](
		1*time.Hour, 5*time.Second, func(_ uint32, v coreIpDomainCacheValue, replaced bool) {
			if !replaced {
				c.recycleLookupCache(v.qname, v.ip, v.bitmap)
			}
		})
	return c, nil
}

type dnsRequest struct {
	AddrPortPair
	routingResult *bpfRoutingResult
	isTcp         bool
}

var dnsRequestPool = sync.Pool{New: func() any { return &dnsRequest{} }}

func ObtainDnsRequest(src, dst netip.AddrPort, routingResult *bpfRoutingResult, isTcp bool) *dnsRequest {
	v := dnsRequestPool.Get()
	dq := v.(*dnsRequest)
	dq.Src = src
	dq.Dst = dst
	dq.routingResult = routingResult
	dq.isTcp = isTcp
	return dq
}

func RecycleDnsRequest(q *dnsRequest) {
	dnsRequestPool.Put(q)
}

type dialArgument struct {
	networkType *common.NetworkType
	Dialer      *dialer.Dialer
	Outbound    *outbound.DialerGroup
	Target      netip.AddrPort
	// mark        uint32
}

var dialArgumentPool = sync.Pool{
	New: func() any {
		return &dialArgument{}
	},
}

type singleFlightParam struct {
	dnsForwarderKey
	c    *DnsController
	data []byte
}

type dnsForwarderKey struct {
	upstream     dns.Upstream
	dialArgument dialArgument
}

type queryInfo struct {
	qname string
	qtype uint16
}

type dnsResponseData struct {
	respData []byte
	fromPool bool
	isNew    bool

	upstreamFrom *dns.Upstream
}

var dnsResponseDataPool = sync.Pool{
	New: func() any {
		return &dnsResponseData{}
	},
}

type dnsCacheKey struct {
	queryInfo
	outbound *outbound.DialerGroup
}

func (c *DnsController) GetHashKey(d dnsCacheKey) HashKey {
	// 1. 获取字符串的基础哈希（汇编加速）
	h1 := maphash.String(c.dnsCacheHashSeed, d.qname)

	// 2. 混入 qtype 和 outbound 指针
	// 建议：使用异或配合位移，减少冲突概率
	h1 ^= uint64(d.qtype) << 32
	if d.outbound != nil {
		h1 ^= uint64(uintptr(unsafe.Pointer(d.outbound)))
	}

	// 3. 生成 h2：使用完整的 fmix64 确保 h2 的随机性
	// 这样即便 h1 的低位发生剧烈变化，h2 也能扩散到高位
	h2 := h1 ^ (h1 >> 33)
	h2 *= 0xff51afd7ed558ccd
	h2 ^= h2 >> 33
	h2 *= 0xc4ceb9fe1a85ec53
	h2 ^= h2 >> 33

	return HashKey{h1, h2}
}

func dnsQueryInfo(data []byte) (queryInfo queryInfo) {
	if qname, off, err := dnsDomain(data, 12); err == nil {
		if len(data) >= off+4 {
			qtype := binary.BigEndian.Uint16(data[off : off+2])
			qclass := binary.BigEndian.Uint16(data[off+2 : off+4])
			if qclass == uint16(dnsmessage.ClassINET) {
				queryInfo.qname = common.CanonicalName(qname)
				queryInfo.qtype = qtype
			}
		}
	}
	return
}

func (c *DnsController) Handle(data []byte, req *dnsRequest) bool {
	if len(data) < 12 {
		return false
	}

	dnsResponseSet(data, false)

	queryInfo := dnsQueryInfo(data)
	if log.IsLevelEnabled(log.TraceLevel) {
		log.Tracef("Received UDP(DNS) %v <-> %v: %v %v",
			RefineSourceToShow(req.Src, req.Dst.Addr()), req.Dst.String(), queryInfo.qname, queryInfo.qtype)
	}

	id := dnsId(data)
	// Avoids duplicated id from clients, so make the id unique.
	dnsIdSet(data, uint16(fastrand.Intn(math.MaxUint16)))

	// Get pooled dnsResponseData and pass it as output parameter.
	dnsResp := dnsResponseDataPool.Get().(*dnsResponseData)
	defer func() {
		if dnsResp.respData != nil && dnsResp.fromPool {
			pool.PutBuffer(dnsResp.respData)
		}
		dnsResponseDataPool.Put(dnsResp)
	}()

	var err error
	// Check ip version preference and qtype.
	switch queryInfo.qtype {
	case dnsmessage.TypeA, dnsmessage.TypeAAAA:
		if c.qtypePrefer == 0 {
			err = c.handleDNSRequest(data, req, queryInfo, dnsResp)
		} else {
			// Try to make both A and AAAA lookups.
			// TODO: ignoreFixedTTL?
			type alternateResult struct {
				err       error
				hasAnswer bool
			}
			resultCh := make(chan *alternateResult, 1)
			go func() {
				dnsResp2 := dnsResponseDataPool.Get().(*dnsResponseData)
				data2 := pool.GetBuffer(len(data))
				defer func() {
					pool.PutBuffer(data2)
					if dnsResp2.respData != nil && dnsResp2.fromPool {
						pool.PutBuffer(dnsResp2.respData)
					}
					dnsResponseDataPool.Put(dnsResp2)
				}()
				copy(data2, data)
				dnsSwitchQtype(data2)
				err := c.handleDNSRequest(data2, req, queryInfo, dnsResp2)
				if err != nil {
					resultCh <- &alternateResult{err: err}
					return
				}
				ips, _ := dnsAnswers(dnsResp2.respData)
				resultCh <- &alternateResult{hasAnswer: len(ips) > 0}
			}()
			err = c.handleDNSRequest(data, req, queryInfo, dnsResp)
			result := <-resultCh
			err = common.Join(err, result.err)
			if err != nil {
				break
			}
			if c.qtypePrefer != queryInfo.qtype && result.hasAnswer && dnsResp.respData != nil {
				c.reject(dnsResp.respData)
			}
		}
	default:
		err = c.handleDNSRequest(data, req, queryInfo, dnsResp)
	}
	dataToWrite := dnsResp.respData
	if err != nil {
		netErr, ok := IsNetError(err)
		if !ok || !netErr.Temporary() {
			log.Errorf("%+v", err)
		}
		dataToWrite = data
		dnsRcodeSet(dataToWrite, dnsmessage.RcodeServerFailure)
	}
	// Keep the id the same with request.
	dnsIdSet(dataToWrite, id)

	// Send back the dns response.
	// Never recycle anyfrom for Non-ASIS upstreams because they are limited.
	// Note: zero-ttl means "immortal".
	var ttl time.Duration
	if dnsResp.upstreamFrom != nil && dnsResp.upstreamFrom.IsAsIs {
		ttl = AnyfromTimeoutDefault
	}
	af, err := DefaultAnyfromPool.Obtain(req.Dst, ttl)
	if err == nil {
		_, err = af.WriteToUDPAddrPort(dataToWrite, req.Src)
		DefaultAnyfromPool.Recycle(req.Dst, af)
	}
	if err != nil {
		log.Warningf("failed to send dns message back: %v", err)
	}
	return true
}

// TODO: 除了dialSend, 不应该有可预期的 err
// TODO: qname=. qtype=2 的查询是什么, 为什么没有缓存, 因为AsIs?
// TODO: 如果AsIs都不缓存的话，如果一个server可用一个不可用，那就是远端sever的问题?
func (c *DnsController) handleDNSRequest(
	data []byte,
	req *dnsRequest,
	queryInfo queryInfo,
	dnsResp *dnsResponseData,
) error {
	var err error
	// Route Requset
	hashKey := c.GetHashKey(dnsCacheKey{queryInfo: queryInfo, outbound: nil})
	RequestIndex, ok := c.requestSelectCache.Get(hashKey)
	if !ok {
		RequestIndex, err = c.routing.RequestSelect(queryInfo.qname, queryInfo.qtype)
		if err != nil {
			return err
		}
		c.requestSelectCache.Save(hashKey, RequestIndex)
	}

	if RequestIndex == consts.DnsRequestOutboundIndex_Reject {
		c.reject(data)
		dnsResp.respData = data
		dnsResp.fromPool = false
		dnsResp.isNew = false
		return nil
	}

	var upstream *dns.Upstream
	if RequestIndex == consts.DnsRequestOutboundIndex_AsIs {
		// As-is should not be valid in response routing, thus using connection realDest is reasonable.
		upstream = &dns.Upstream{
			Scheme:   "udp",
			Hostname: req.Dst.Addr().String(),
			Port:     req.Dst.Port(),
			Ip46:     netutils.FromAddr(req.Dst.Addr()),
			IsAsIs:   true,
		}
	} else {
		// Get corresponding upstream.
		upstream, err = c.routing.GetUpstream(RequestIndex)
		if err != nil {
			return err
		}
	}

	// Dial and re-route
	dialArgument := dialArgumentPool.Get().(*dialArgument)
	defer dialArgumentPool.Put(dialArgument)
Dial:
	for invokingDepth := 1; invokingDepth <= MaxDnsLookupDepth; invokingDepth++ {
		if log.IsLevelEnabled(log.DebugLevel) {
			log.WithFields(log.Fields{
				"qname":    queryInfo.qname,
				"upstream": upstream.String(),
			}).Debugln("Request to DNS upstream")
		}

		// Select best dial arguments (outbound, dialer, l4proto, ipversion, etc.)
		if err := c.bestDialerChooser(req, upstream, dialArgument); err != nil {
			return err
		}

		// TODO: 这里可能不可以这样做
		if err = c.dialSend(data, upstream, dialArgument, queryInfo, dnsResp); err != nil {
			netErr, ok := IsNetError(err)
			if !ok || !dnsResponse(dnsResp.respData) || (!netErr.Timeout() && dialArgument.Dialer.NeedAliveState()) {
				err = common.
					In("DialContext").
					With("Is NetError", ok).
					With("Is Temporary", ok && netErr.Temporary()).
					With("Is Timeout", ok && netErr.Timeout()).
					With("qname", queryInfo.qname).
					With("qtype", queryInfo.qtype).
					With("Outbound", dialArgument.Outbound.Name).
					With("Dialer", dialArgument.Dialer.Name).
					Wrapf(err, "DNS dialSend error")
				if !ok || !dnsResponse(dnsResp.respData) {
					return err
				} else if !netErr.Timeout() && dialArgument.Dialer.NeedAliveState() {
					labels := [...]string{
						dialArgument.Outbound.Name,
						dialArgument.Dialer.Property.SubscriptionTag,
						dialArgument.Dialer.Name,
						dialArgument.networkType.String(),
					}
					common.Metrics.ErrorCount.With4(labels).Inc()
					dialArgument.Dialer.ReportUnavailable()
					return err
				}
			}
		}
		if !c.routing.HasResponseRules() {
			if dnsResp.isNew {
				c.logDnsResponse(req, dialArgument, queryInfo, true)
			}
			break Dial
		}
		// Route response.
		var ResponseIndex consts.DnsResponseOutboundIndex
		var nextUpstream *dns.Upstream
		ips, _ := dnsAnswers(dnsResp.respData)
		ResponseIndex, nextUpstream, err = c.routing.ResponseSelect(queryInfo.qname, queryInfo.qtype, ips, upstream)
		if err != nil {
			return err
		}
		if ResponseIndex.IsReserved() {
			if dnsResp.isNew {
				c.logDnsResponse(req, dialArgument, queryInfo, ResponseIndex == consts.DnsResponseOutboundIndex_Accept)
			}
			switch ResponseIndex {
			case consts.DnsResponseOutboundIndex_Reject:
				// Reject
				// TODO: cache response reject.
				c.reject(dnsResp.respData)
				fallthrough
			case consts.DnsResponseOutboundIndex_Accept:
				// Accept.
				break Dial
			default:
				return common.Errf("unknown upstream: %v", ResponseIndex.String())
			}
		}
		if invokingDepth == MaxDnsLookupDepth {
			return common.Errf("too deep DNS lookup invoking (depth: %v); there may be infinite loop in your DNS response routing", MaxDnsLookupDepth)
		}
		if log.IsLevelEnabled(log.DebugLevel) {
			log.WithFields(log.Fields{
				"qname":         queryInfo.qname,
				"last_upstream": upstream.String(),
				"next_upstream": nextUpstream.String(),
			}).Debugln("Change DNS upstream and resend")
		}
		upstream = nextUpstream
		if dnsResp.respData != nil && dnsResp.fromPool {
			pool.PutBuffer(dnsResp.respData)
		}
	}
	// TODO: dial_mode: domain 的逻辑失效问题
	// TODO: 我们现在缓存了它, 但并不响应缓存, 这是一个workround, 会导致污染其他非AsIs的查询
	// TODO: AsIs也需要更新domain_routing_map? 不然没有办法sniff, 并且考虑到有些应用会使用不同的DNS, 必须对全部 upstream 更新
	// TODO: RemoveCache
	// TODO: 不再存储Bitmap, 提高更新代码可读性
	// 但在有bump_map的情况下这不是大问题
	// TOOD: 细分日志
	if dnsResp.isNew && isDnsResponseValid(dnsResp.respData) {
		domainBitmap := common.ObtainDomainBitmap()
		defer common.RecycleDomainBitmap(domainBitmap)
		if allZero, shouldUpdate := c.checkDomainBitmap(queryInfo.qname, domainBitmap); shouldUpdate {
			ips, ttl := dnsAnswers(dnsResp.respData)
			err = c.updateLookupCache(queryInfo.qname, domainBitmap, allZero, ips, time.Duration(ttl)*time.Second)
		}
	}
	return err
}

func (c *DnsController) logDnsResponse(req *dnsRequest, dialArgument *dialArgument, queryInfo queryInfo, accepted bool) {
	if log.IsLevelEnabled(log.InfoLevel) {
		fields := log.Fields{
			"network":  dialArgument.networkType.String(),
			"outbound": dialArgument.Outbound.Name,
			"policy":   dialArgument.Outbound.GetSelectionPolicy(),
			"dialer":   dialArgument.Dialer.Name,
			"qname":    queryInfo.qname,
			"qtype":    queryInfo.qtype,
			"pid":      req.routingResult.Pid,
			"ifindex":  req.routingResult.Ifindex,
			"dscp":     req.routingResult.Dscp,
			"pname":    ProcessName2String(req.routingResult.Pname[:]),
			"mac":      Mac2String(req.routingResult.Mac[:]),
		}
		var source string
		if req.isTcp {
			source = fmt.Sprintf("[DNS(TCP)] %s", RefineSourceToShow(req.Src, req.Dst.Addr()))
		} else {
			source = fmt.Sprintf("[DNS] %s", RefineSourceToShow(req.Src, req.Dst.Addr()))
		}
		var target string
		if dialArgument.Target == req.Dst {
			target = RefineAddrPortToShow(dialArgument.Target)
		} else {
			target = fmt.Sprintf("%s (%s)", RefineAddrPortToShow(dialArgument.Target), RefineAddrPortToShow(req.Dst))
		}
		if accepted {
			log.WithFields(fields).Infof("%s <-> %s", source, target)
		} else {
			log.WithFields(fields).Infof("%s <-> %s Reject with empty answer", source, target)
		}
	}
}

func (c *DnsController) checkDomainBitmap(qname string, domainBitmap []uint32) (allZero bool, shouldUpdateLookupCache bool) {
	c.matchBitmap(qname, domainBitmap)
	allZero = true
	for _, v := range domainBitmap {
		if v != 0 {
			allZero = false
			break
		}
	}
	// When SniffVerifyMode is 'loose' and no record in deadline timers, ControlPlane would try
	// to resolve IPs for sniffing verification, which might cause dns leaks! So only skip the
	// lookup cache update when SniffVerifyMode isn't 'loose'.
	shouldUpdateLookupCache = !allZero || c.sniffVerifyMode == consts.SniffVerifyMode_Loose
	return
}

func (c *DnsController) updateLookupCache(qname string, domainBitmap []uint32, allZero bool, ips []netip.Addr, ttl time.Duration) error {
	if len(ips) == 0 {
		return nil
	}
	lookupTTL := max(ttl, c.minSniffingTtl)
	bitmap := (*[32]uint32)(domainBitmap)

	c.mu.Lock()
	defer c.mu.Unlock()

	for _, ip := range ips {
		if _, ok := c.lookupCache[qname]; !ok {
			c.lookupCache[qname] = make(map[netip.Addr]uint32)
		}
		if h, ok := c.lookupCache[qname][ip]; ok {
			c.coreIpDomainCache.SaveWithTTL(h, coreIpDomainCacheValue{qname: qname, ip: ip, bitmap: bitmap}, lookupTTL)
			continue
		}
		if allZero {
			continue
		}
		if err := c.newLookupCache(ip, bitmap); err != nil {
			return err
		}
		hash := lookupHash(qname, ip)
		c.lookupCache[qname][ip] = hash
		c.coreIpDomainCache.SaveWithTTL(hash, coreIpDomainCacheValue{qname: qname, ip: ip, bitmap: bitmap}, lookupTTL)
		common.Metrics.CoreIpDomainBitmap.With0().Inc()
	}
	return nil
}

func (c *DnsController) recycleLookupCache(qname string, ip netip.Addr, bitmap *[32]uint32) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if err := c.lookupCacheTimeout(ip, bitmap); err == nil {
		common.Metrics.CoreIpDomainBitmap.With0().Dec()
	}
	delete(c.lookupCache[qname], ip)
	if len(c.lookupCache[qname]) == 0 {
		delete(c.lookupCache, qname)
	}
}

// 使用简单的 hash 组合 qname 和 ip
func lookupHash(qname string, ip netip.Addr) uint32 {
	h := crc32.NewIEEE()
	h.Write([]byte(qname))
	h.Write(ip.AsSlice())
	return h.Sum32()
}

func (c *DnsController) MaybeUpdateLookupCache(qname string, ips []netip.Addr, ttl time.Duration) error {
	if len(ips) == 0 {
		return nil
	}
	domainBitmap := common.ObtainDomainBitmap()
	defer common.RecycleDomainBitmap(domainBitmap)
	if allZero, shouldUpdate := c.checkDomainBitmap(qname, domainBitmap); shouldUpdate {
		return c.updateLookupCache(qname, domainBitmap, allZero, ips, ttl)
	}
	return nil
}

func (c *DnsController) reject(data []byte) {
	if len(data) < 12 {
		return
	}
	data[2] |= 0x80           // 设置 QR = 1
	data[2] &= 0xFD           // 强制设置 TC = 0 (0xFD 是 11111101)
	data[3] = 0x80            // RA=1
	data[6], data[7] = 0, 0   // ANCOUNT = 0
	data[8], data[9] = 0, 0   // NSCOUNT = 0
	data[10], data[11] = 0, 0 // ARCOUNT = 0
}

type dnsRefreshParam struct {
	data     []byte
	cacheKey dnsCacheKey
	upstream *dns.Upstream
	dialArg  dialArgument
}

var dnsRefreshParamPool = sync.Pool{
	New: func() any { return &dnsRefreshParam{} },
}

func obtainDnsRefreshParam(data []byte, cacheKey dnsCacheKey, upstream *dns.Upstream, dialArg *dialArgument) *dnsRefreshParam {
	p := dnsRefreshParamPool.Get().(*dnsRefreshParam)
	dataCopy := pool.GetBuffer(len(data))
	copy(dataCopy, data)
	p.data = dataCopy
	p.cacheKey = cacheKey
	p.upstream = upstream
	p.dialArg = *dialArg
	return p
}

func recycleDnsRefreshParam(p *dnsRefreshParam) {
	pool.PutBuffer(p.data)
	p.data = nil
	dnsRefreshParamPool.Put(p)
}

func (c *DnsController) dialSend(data []byte, upstream *dns.Upstream, dialArg *dialArgument, queryInfo queryInfo, dnsResp *dnsResponseData) error {
	cacheKey := dnsCacheKey{queryInfo: queryInfo, outbound: dialArg.Outbound}
	// Lookup Cache
	if c.enableCache {
		if respData, expired, isNew := c.dnsCache.Get(c.GetHashKey(cacheKey)); respData != nil {
			if expired {
				// Refresh cache asynchronously.
				go c.refreshDnsCache(obtainDnsRefreshParam(data, cacheKey, upstream, dialArg))
			}
			if log.IsLevelEnabled(log.DebugLevel) {
				log.WithFields(log.Fields{
					"answer": FormatDnsRsc(respData),
				}).Debugf("UDP(DNS) <-> Cache: %v %v", queryInfo.qname, queryInfo.qtype)
			}
			// Use the caller's pooled dnsResp to avoid extra allocation.
			dnsResp.respData = respData
			dnsResp.fromPool = true
			dnsResp.isNew = isNew
			dnsResp.upstreamFrom = upstream
			return nil
		}
	}
	// Pending for the same lookup.
	respData, leader, shared, err := c.singleFlightForwardDNS(cacheKey, data, upstream, dialArg, false)
	dnsResp.isNew = leader
	dnsResp.upstreamFrom = upstream
	if respData != nil {
		if !shared {
			dnsResp.respData = respData
			dnsResp.fromPool = false
		} else {
			// Each dns handler goroutine should NOT share the same response data.
			dnsResp.respData = pool.GetBuffer(len(respData))
			copy(dnsResp.respData, respData)
			dnsResp.fromPool = true
		}
		dnsIdSet(dnsResp.respData, dnsId(data)) // keep the same id with request
	}
	return err
}

func (c *DnsController) refreshDnsCache(p *dnsRefreshParam) {
	defer recycleDnsRefreshParam(p)
	if _, _, _, err := c.singleFlightForwardDNS(p.cacheKey, p.data, p.upstream, &p.dialArg, true); err != nil {
		log.Warnf("failed to refresh dns cache for %v: %+v", p.cacheKey, err)
	}
}

func (c *DnsController) singleFlightForwardDNS(
	cacheKey dnsCacheKey, data []byte, upstream *dns.Upstream, dialArgument *dialArgument, isBackground bool) (r []byte, leader bool, shared bool, err error) {
	param := singleFlightParam{dnsForwarderKey: dnsForwarderKey{upstream: *upstream, dialArgument: *dialArgument}, c: c, data: data}
	r, err, leader, shared = c.singleFlightGroup.Do(cacheKey, param, func(p singleFlightParam) ([]byte, error) {
		var forwarder DnsForwarder
		// get forwarder from cache
		value, ok := p.c.dnsForwarderCache.Load(p.dnsForwarderKey)
		if ok {
			forwarder = value.(DnsForwarder)
		} else {
			var err error
			if p.upstream.Scheme == dns.UpstreamScheme_Static {
				forwarder = &StaticForwarder{
					name:    p.upstream.Hostname,
					routing: p.c.routing,
				}
			} else {
				forwarder, err = newDnsForwarder(&p.upstream, p.dialArgument)
			}
			if err != nil {
				return nil, err
			}
			// Try to store the new forwarder, but use LoadOrStore to handle concurrent creation
			actualValue, _ := p.c.dnsForwarderCache.LoadOrStore(p.dnsForwarderKey, forwarder)
			forwarder = actualValue.(DnsForwarder)
		}

		return forwarder.ForwardDNS(p.data)
	})
	if err != nil || r == nil {
		return nil, false, false, err
	}
	if !dnsResponse(r) {
		return nil, false, false, common.Errf("DNS message response flag is unset")
	}
	if leader {
		rcode := dnsRcode(r)
		if log.IsLevelEnabled(log.DebugLevel) {
			log.WithFields(log.Fields{
				"qname": cacheKey.qname,
				"qtype": cacheKey.qtype,
				"rcode": rcode,
				"ans":   FormatDnsRsc(r),
			}).Debugf("Got DNS response")
		}
		if !isDnsResponseValid(r) {
			if log.IsLevelEnabled(log.DebugLevel) {
				log.WithFields(log.Fields{
					"qname": cacheKey.qname,
					"qtype": cacheKey.qtype,
					"rcode": rcode,
					"ans":   FormatDnsRsc(r),
				}).Debugf("Not a valid DNS response")
			}
		} else if c.enableCache && shouldSaveToCache(upstream, cacheKey.qname) {
			if log.IsLevelEnabled(log.DebugLevel) {
				log.WithFields(log.Fields{
					"qname":    cacheKey.qname,
					"qtype":    cacheKey.qtype,
					"rcode":    rcode,
					"ans":      FormatDnsRsc(r),
					"upstream": upstream,
					"dialer":   dialArgument.Dialer,
					"outbound": dialArgument.Outbound,
				}).Debugf("Update DNS record cache")
			}
			// Direct hold r in cache when shared, because it will be copied before sending back to clients.
			if newCache := c.dnsCache.NewCache(r, c.fixedDomainTtl[cacheKey.qname], isBackground || shared); newCache != nil {
				c.dnsCache.Save(c.GetHashKey(cacheKey), newCache)
			}
		}
	}
	return r, leader, shared, err
}

func shouldSaveToCache(upstream *dns.Upstream, qname string) bool {
	// Skip cache for static entries to allow dynamic updates
	if upstream.Scheme == dns.UpstreamScheme_Static {
		return false
	}
	if len(qname) <= 24 {
		return true
	}
	subLen := strings.IndexByte(qname, '.')
	if subLen <= 0 {
		return false
	}
	if subLen < 10 {
		return true
	}

	var score int
	for i := 0; i < subLen; i++ {
		c := qname[i]
		if (c >= '0' && c <= '9') || c == '-' {
			score++
		}
	}

	if subLen <= 16 {
		return score*2 <= subLen
	}
	return score*3 <= subLen
}

func (c *DnsController) GetStaticEntries() map[string]*config.DnsStaticEntry {
	return c.routing.GetStaticEntries()
}

func (c *DnsController) GetStaticEntry(name string) (*config.DnsStaticEntry, bool) {
	return c.routing.GetStaticEntry(name)
}

func (c *DnsController) UpdateStaticEntry(name string, entry *config.DnsStaticEntry) error {
	return c.routing.UpdateStaticEntry(name, entry)
}

func (c *DnsController) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.requestSelectCache.Close()
	c.dnsCache.Close()

	// Clean up cache & deadline timers.
	c.coreIpDomainCache.Close()
	c.lookupCache = make(map[string]map[netip.Addr]uint32)

	// Close all DNS forwarders
	c.dnsForwarderCache.Range(func(key, value any) bool {
		if forwarder, ok := value.(io.Closer); ok {
			forwarder.Close()
		}
		return true
	})
	return nil
}
