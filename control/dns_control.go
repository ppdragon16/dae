/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"encoding/binary"
	"fmt"
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
	qHash  HashKey
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
	lookupCache       map[HashKey]uint16                                      // Key: Hash by qname
	coreIpDomainCache *common.TimeWheelCache[HashKey, coreIpDomainCacheValue] // Key: Hash by qname + ip
	sniffVerifyMode   consts.SniffVerifyMode

	singleFlightGroup common.SingleFlight[HashKey, []byte, singleFlightParam] // Key: Hash by qname + ip + *outbound
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
		lookupCache:        make(map[HashKey]uint16),
	}
	c.coreIpDomainCache = common.NewTimeWheelCache[HashKey, coreIpDomainCacheValue](
		1*time.Hour, 5*time.Second, func(_ HashKey, v coreIpDomainCacheValue, replaced bool) {
			if !replaced {
				c.recycleLookupCache(v.qHash, v.ip, v.bitmap)
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
	c            *DnsController
	data         []byte
	qi           queryInfo
	isBackground bool
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

func (c *DnsController) GetHashKey(qname string, qtype uint16, outbound *outbound.DialerGroup, dialer *dialer.Dialer) HashKey {
	// 1. 获取字符串的基础哈希（汇编加速）
	h1 := maphash.String(c.dnsCacheHashSeed, qname)

	// 2. 混入 qtype 和 outbound/dialer/cache-tag
	h1 ^= uint64(qtype) << 32
	if outbound != nil {
		// If the dialer has a dns_cache_tag annotation, use it as the cache domain.
		// Dialers with the same tag share DNS cache; different tags are isolated.
		if dialer != nil {
			if anno := outbound.GetAnnotation(dialer); anno != nil && anno.DnsCacheTag != "" {
				h1 ^= maphash.String(c.dnsCacheHashSeed, anno.DnsCacheTag)
				return HashKey(h1)
			}
		}
		h1 ^= uint64(uintptr(unsafe.Pointer(outbound)))
	}
	return HashKey(h1)
}

func (c *DnsController) QnameHash(qname string) HashKey {
	return HashKey(maphash.String(c.dnsCacheHashSeed, qname))
}

func QnameIpHash(qhash HashKey, ip netip.Addr) HashKey {
	h1 := uint64(qhash)
	addr := ip.As16()
	h1 ^= binary.LittleEndian.Uint64(addr[0:8])
	h1 ^= binary.LittleEndian.Uint64(addr[8:16])
	return HashKey(h1)
}

func (c *DnsController) hashKeyForDnsRequest(qname string, qtype uint16, srcMac [6]byte, srcIp netip.Addr) HashKey {
	h1 := uint64(c.GetHashKey(qname, qtype, nil, nil))
	if !c.routing.HasClientRequestRules() {
		return HashKey(h1)
	}
	// Mix in MAC (6 bytes, zero-padded to 8).
	var mac8 [8]byte
	copy(mac8[:], srcMac[:])
	h1 ^= binary.LittleEndian.Uint64(mac8[:])
	if srcIp.IsValid() {
		// Mix in source IP (16 bytes as two uint64).
		addr := srcIp.As16()
		h1 ^= binary.LittleEndian.Uint64(addr[0:8])
		h1 ^= binary.LittleEndian.Uint64(addr[8:16])
	}
	return HashKey(h1)
}

func dnsQueryInfo(data []byte) (queryInfo queryInfo) {
	qname, qtype, ok := dnsQuestion(data)
	if !ok {
		return
	}
	queryInfo.qname = qname
	queryInfo.qtype = qtype
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

	// qname is empty when dnsQuestion failed to parse the question section
	// (malformed packet, non-INET class, etc.). Return false so the data
	// falls through to regular UDP routing.
	if queryInfo.qname == "" {
		return false
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
		*dnsResp = dnsResponseData{}
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
					*dnsResp2 = dnsResponseData{}
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
		isNetError, _, _, isTemporary := GetNetErrorInfo(err)
		if !isNetError || !isTemporary {
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
	// Route Request.
	hashKey := c.hashKeyForDnsRequest(queryInfo.qname, queryInfo.qtype, req.routingResult.Mac, req.Src.Addr())
	RequestIndex, ok := c.requestSelectCache.Get(hashKey)
	if !ok {
		var err error
		RequestIndex, err = c.routing.RequestSelect(queryInfo.qname, queryInfo.qtype, req.routingResult.Mac, req.Src.Addr())
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

	// Check for race group: race(upstream1, upstream2, ...)
	if raceUpstreams := c.routing.GetRaceUpstreams(RequestIndex); len(raceUpstreams) > 0 {
		return c.handleDNSRequestRace(data, req, queryInfo, dnsResp, raceUpstreams)
	}

	// Resolve the single upstream and dial.
	var upstream *dns.Upstream
	if RequestIndex == consts.DnsRequestOutboundIndex_AsIs {
		upstream = &dns.Upstream{
			Scheme:   "udp",
			Hostname: req.Dst.Addr().String(),
			Port:     req.Dst.Port(),
			Ip46:     netutils.FromAddr(req.Dst.Addr()),
			IsAsIs:   true,
		}
	} else {
		var err error
		upstream, err = c.routing.GetUpstream(RequestIndex)
		if err != nil {
			return err
		}
	}

	return c.handleDNSRequestByUpstream(data, req, queryInfo, upstream, dnsResp)
}

// handleDNSRequestByUpstream selects the best dialer, sends DNS query, handles response
// routing, logging, and lookup cache update. It manages dialArgument lifecycle internally.
// Caller provides a pre-allocated dnsResp as the output parameter.
func (c *DnsController) handleDNSRequestByUpstream(
	data []byte,
	req *dnsRequest,
	queryInfo queryInfo,
	upstream *dns.Upstream,
	dnsResp *dnsResponseData,
) error {
	dialArgument := dialArgumentPool.Get().(*dialArgument)
	defer dialArgumentPool.Put(dialArgument)

	var err error
Dial:
	for invokingDepth := 1; invokingDepth <= MaxDnsLookupDepth; invokingDepth++ {
		if log.IsLevelEnabled(log.DebugLevel) {
			log.WithFields(log.Fields{
				"qname":    queryInfo.qname,
				"upstream": upstream.String(),
			}).Debugln("Request to DNS upstream")
		}

		// Select best dial arguments and send DNS query.
		if err = c.bestDialerChooser(req, upstream, dialArgument); err != nil {
			return err
		}
		if err = c.dialSend(data, upstream, dialArgument, queryInfo, dnsResp); err != nil {
			isNetError, isClosed, isTimeout, isTemporary := GetNetErrorInfo(err)
			if !isNetError || isClosed || !dnsResponse(dnsResp.respData) || (!isTimeout && dialArgument.Dialer.NeedAliveState()) {
				err = common.
					In("DialContext").
					With("Is NetError", isNetError).
					With("Is Temporary", isTemporary).
					With("Is Timeout", isTimeout).
					With("qname", queryInfo.qname).
					With("qtype", queryInfo.qtype).
					With("Outbound", dialArgument.Outbound.Name).
					With("Dialer", dialArgument.Dialer.Name).
					Wrapf(err, "DNS dialSend error")
				if !isNetError || isClosed || !dnsResponse(dnsResp.respData) {
					return err
				} else if !isTimeout && dialArgument.Dialer.NeedAliveState() {
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
				c.reject(dnsResp.respData)
				fallthrough
			case consts.DnsResponseOutboundIndex_Accept:
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

// handleDNSRequestRace sends DNS queries to multiple upstreams concurrently and uses the
// first successful response. Each sub-upstream independently goes through the full
// handleDNSRequestByUpstream path (including response routing).
func (c *DnsController) handleDNSRequestRace(
	data []byte,
	req *dnsRequest,
	queryInfo queryInfo,
	dnsResp *dnsResponseData,
	raceUpstreams []*dns.Upstream,
) error {
	var mu sync.Mutex
	var wg sync.WaitGroup
	var winnerResp *dnsResponseData
	var firstErr error

	for _, upstream := range raceUpstreams {
		wg.Add(1)
		go func(upstream *dns.Upstream) {
			defer wg.Done()

			localResp := dnsResponseDataPool.Get().(*dnsResponseData)
			isWinner := false
			defer func() {
				if isWinner {
					// Ownership transferred to main goroutine; skip cleanup.
					return
				}
				if localResp.respData != nil && localResp.fromPool {
					pool.PutBuffer(localResp.respData)
				}
				*localResp = dnsResponseData{}
				dnsResponseDataPool.Put(localResp)
			}()

			err := c.handleDNSRequestByUpstream(data, req, queryInfo, upstream, localResp)

			mu.Lock()
			if err == nil && winnerResp == nil {
				winnerResp = localResp
				isWinner = true
			}
			if err != nil && firstErr == nil {
				firstErr = err
			}
			mu.Unlock()
		}(upstream)
	}
	wg.Wait()

	if winnerResp == nil {
		if firstErr != nil {
			return fmt.Errorf("all %d race upstreams failed: %w", len(raceUpstreams), firstErr)
		}
		return fmt.Errorf("all %d race upstreams failed", len(raceUpstreams))
	}

	// Transfer winner's data to caller's dnsResp, then recycle the struct.
	dnsResp.respData = winnerResp.respData
	dnsResp.fromPool = winnerResp.fromPool
	dnsResp.isNew = winnerResp.isNew
	dnsResp.upstreamFrom = winnerResp.upstreamFrom
	*winnerResp = dnsResponseData{}
	dnsResponseDataPool.Put(winnerResp)
	return nil
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

	qHash := c.QnameHash(qname)

	c.mu.Lock()
	defer c.mu.Unlock()

	if _, ok := c.lookupCache[qHash]; !ok {
		c.lookupCache[qHash] = 0
	}

	for _, ip := range ips {
		hashKey := QnameIpHash(qHash, ip)
		if _, ok := c.coreIpDomainCache.Get(hashKey); ok {
			// Just update ttl, no need to update ebpf map.
			c.coreIpDomainCache.SaveWithTTL(hashKey, coreIpDomainCacheValue{qHash: qHash, ip: ip, bitmap: bitmap}, lookupTTL)
			continue
		}
		// allZero could be true when SniffVerifyMode is 'loose'. It means no need to update ebpf map, but still need to
		// update lookup cache because VerifySniff needs to know domain-ip existence.
		if !allZero {
			go newLookupCacheAsync(c, ip, bitmap)
		}
		c.lookupCache[qHash]++
		c.coreIpDomainCache.SaveWithTTL(hashKey, coreIpDomainCacheValue{qHash: qHash, ip: ip, bitmap: bitmap}, lookupTTL)
		common.Metrics.CoreIpDomainBitmap.With0().Inc()
	}
	return nil
}

func (c *DnsController) recycleLookupCache(qHash HashKey, ip netip.Addr, bitmap *[32]uint32) {
	go lookupCacheTimeoutAsync(c, ip, bitmap)
	common.Metrics.CoreIpDomainBitmap.With0().Dec()

	c.mu.Lock()
	defer c.mu.Unlock()

	if n, ok := c.lookupCache[qHash]; ok {
		if n > 1 {
			c.lookupCache[qHash] = n - 1
			return
		}
		delete(c.lookupCache, qHash)
	}
}

func newLookupCacheAsync(c *DnsController, ip netip.Addr, domainBitmap *[32]uint32) {
	if err := c.newLookupCache(ip, domainBitmap); err != nil {
		log.Errorf("failed to update lookup cache to ebpf for ip %v: %v", ip, err)
	}
}

func lookupCacheTimeoutAsync(c *DnsController, ip netip.Addr, domainBitmap *[32]uint32) {
	if err := c.lookupCacheTimeout(ip, domainBitmap); err != nil {
		log.Errorf("failed to delete lookup cache from ebpf for ip %v: %v", ip, err)
	}
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
	qi       queryInfo
	upstream *dns.Upstream
	dialArg  dialArgument
}

var dnsRefreshParamPool = sync.Pool{
	New: func() any { return &dnsRefreshParam{} },
}

func obtainDnsRefreshParam(data []byte, qi queryInfo, upstream *dns.Upstream, dialArg *dialArgument) *dnsRefreshParam {
	p := dnsRefreshParamPool.Get().(*dnsRefreshParam)
	dataCopy := pool.GetBuffer(len(data))
	copy(dataCopy, data)
	p.data = dataCopy
	p.qi = qi
	p.upstream = upstream
	p.dialArg = *dialArg
	return p
}

func recycleDnsRefreshParam(p *dnsRefreshParam) {
	pool.PutBuffer(p.data)
	p.data = nil
	p.upstream = nil
	p.qi = queryInfo{}
	p.dialArg = dialArgument{}
	dnsRefreshParamPool.Put(p)
}

func (c *DnsController) dialSend(data []byte, upstream *dns.Upstream, dialArg *dialArgument, queryInfo queryInfo, dnsResp *dnsResponseData) error {
	// Lookup Cache
	if c.enableCache {
		if respData, expired, isNew := c.dnsCache.Get(c.GetHashKey(queryInfo.qname, queryInfo.qtype, dialArg.Outbound, dialArg.Dialer)); respData != nil {
			if expired {
				// Refresh cache asynchronously.
				go func(c *DnsController, p *dnsRefreshParam) {
					defer recycleDnsRefreshParam(p)
					if _, _, _, err := c.singleFlightForwardDNS(p.qi, p.data, p.upstream, &p.dialArg, true); err != nil {
						log.Warnf("failed to refresh dns cache for %v: %+v", p.qi, err)
					}
				}(c, obtainDnsRefreshParam(data, queryInfo, upstream, dialArg))
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
			dnsIdSet(dnsResp.respData, dnsId(data))
			return nil
		}
	}
	// Pending for the same lookup.
	respData, leader, shared, err := c.singleFlightForwardDNS(queryInfo, data, upstream, dialArg, false)
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

func (c *DnsController) singleFlightForwardDNS(
	qi queryInfo, data []byte, upstream *dns.Upstream, dialArgument *dialArgument, isBackground bool) (r []byte, leader bool, shared bool, err error) {
	hashKey := c.GetHashKey(qi.qname, qi.qtype, dialArgument.Outbound, dialArgument.Dialer)
	param := singleFlightParam{
		dnsForwarderKey: dnsForwarderKey{upstream: *upstream, dialArgument: *dialArgument},
		c:               c,
		data:            data,
		qi:              qi,
		isBackground:    isBackground,
	}
	r, err, leader, shared = c.singleFlightGroup.Do(hashKey, param, func(p singleFlightParam) ([]byte, error) {
		forwarderKey := p.dnsForwarderKey
		upstream := forwarderKey.upstream
		dialArgument := forwarderKey.dialArgument
		c := p.c
		data := p.data
		qname := p.qi.qname
		qtype := p.qi.qtype
		isBackground := p.isBackground

		// get forwarder from cache
		var forwarder DnsForwarder
		value, ok := c.dnsForwarderCache.Load(forwarderKey)
		if ok {
			forwarder = value.(DnsForwarder)
		} else {
			var err error
			if upstream.Scheme == dns.UpstreamScheme_Static {
				forwarder = &StaticForwarder{
					name:    upstream.Hostname,
					routing: c.routing,
				}
			} else {
				forwarder, err = newDnsForwarder(&upstream, dialArgument)
			}
			if err != nil {
				return nil, err
			}
			// Try to store the new forwarder, but use LoadOrStore to handle concurrent creation
			actualValue, _ := c.dnsForwarderCache.LoadOrStore(forwarderKey, forwarder)
			forwarder = actualValue.(DnsForwarder)
		}

		r, err := forwarder.ForwardDNS(data)
		if err != nil {
			return nil, err
		}
		rcode := dnsRcode(r)
		if log.IsLevelEnabled(log.DebugLevel) {
			log.WithFields(log.Fields{
				"qname": qname,
				"qtype": qtype,
				"rcode": rcode,
				"ans":   FormatDnsRsc(r),
			}).Debugf("Got DNS response")
		}
		if !isDnsResponseValid(r) {
			if log.IsLevelEnabled(log.DebugLevel) {
				log.WithFields(log.Fields{
					"qname": qname,
					"qtype": qtype,
					"rcode": rcode,
					"ans":   FormatDnsRsc(r),
				}).Debugf("Not a valid DNS response")
			}
		} else if c.enableCache && shouldSaveToCache(&upstream, qname) {
			if log.IsLevelEnabled(log.DebugLevel) {
				log.WithFields(log.Fields{
					"qname":    qname,
					"qtype":    qtype,
					"rcode":    rcode,
					"ans":      FormatDnsRsc(r),
					"upstream": upstream,
					"dialer":   dialArgument.Dialer,
					"outbound": dialArgument.Outbound,
				}).Debugf("Update DNS record cache")
			}
			key := c.GetHashKey(qname, qtype, dialArgument.Outbound, dialArgument.Dialer)
			fixedTtl := c.fixedDomainTtl[qname]
			c.dnsCache.Save(key, r, fixedTtl, isBackground)
		}
		return r, nil
	})
	if err != nil || r == nil {
		return nil, false, false, err
	}
	if !dnsResponse(r) {
		return nil, false, false, common.Errf("DNS message response flag is unset")
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

// IpDomainLookupResult describes a single qname → IP mapping observed
// in the DNS response cache. The qtype is implicit from the queried IP's
// family (IPv4 only matches A records, IPv6 only matches AAAA), so it
// is not stored. TTL is the remaining seconds at the time of the
// lookup; 0 means the entry is logically expired (but still in the
// cache). Multiple entries with the same qname but different outbounds
// are reported individually — no dedupe.
type IpDomainLookupResult struct {
	QName string
	TTL   uint32
}

// LookupDomainsByIP returns every qname whose cached response contains
// an A or AAAA record equal to ip, along with the remaining TTL for
// that answer. Pure offline scan over the raw response cache.
func (c *DnsController) LookupDomainsByIP(ip netip.Addr) []IpDomainLookupResult {
	var out []IpDomainLookupResult
	c.dnsCache.Range(func(_ HashKey, cache *dnsCache) bool {
		qname, _, ok := dnsQuestion(cache.Data)
		if !ok {
			return true
		}
		elapsed := uint32(time.Since(cache.FetchedAt).Seconds())

		it, iterOK := newDNSRRIterator(cache.Data)
		if !iterOK {
			return true
		}
		// rrIdx tracks the i-th RR in the answer section; TTLOffsets[i] is that
		// RR's TTL byte offset. We rely on netip.Addr's documented invariant
		// that its zero value is invalid and never equals a valid Addr, so
		// non-A/AAAA records (and truncated rdata) leave rrIP as the zero
		// value and the rrIP == ip check below filters them out for free.
		rrIdx := -1
		for off, hasRR := it.Next(); hasRR; off, hasRR = it.Next() {
			rrIdx++
			// Defensive: TTLOffsets is built parallel to all answer RRs in
			// dnsCache.Save, so it should never be shorter than rrIdx. If it
			// is, the cache is corrupted — bail out of this entry rather than
			// doing more doomed iterations.
			if rrIdx >= len(cache.TTLOffsets) {
				break
			}
			rtype := binary.BigEndian.Uint16(cache.Data[off : off+2])
			rdataOff := int(off) + 10
			var rrIP netip.Addr
			switch rtype {
			case 1: // A
				if rdataOff+4 <= len(cache.Data) {
					rrIP = netip.AddrFrom4([4]byte(cache.Data[rdataOff : rdataOff+4]))
				}
			case 28: // AAAA
				if rdataOff+16 <= len(cache.Data) {
					rrIP = netip.AddrFrom16([16]byte(cache.Data[rdataOff : rdataOff+16]))
				}
			}
			if rrIP != ip {
				continue
			}
			ttlOff := cache.TTLOffsets[rrIdx]
			rawTtl := binary.BigEndian.Uint32(cache.Data[ttlOff : ttlOff+4])
			var remaining uint32
			if rawTtl > elapsed {
				remaining = rawTtl - elapsed
			}
			out = append(out, IpDomainLookupResult{
				QName: qname,
				TTL:   remaining,
			})
		}
		return true
	})
	return out
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
	c.lookupCache = make(map[HashKey]uint16)

	// Close all DNS forwarders
	c.dnsForwarderCache.Range(func(key, value any) bool {
		if forwarder, ok := value.(io.Closer); ok {
			forwarder.Close()
		}
		return true
	})
	return nil
}
