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
	"sync/atomic"
	"time"
	"unsafe"

	"github.com/daeuniverse/dae/common"
	"github.com/daeuniverse/dae/common/netutils"

	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/component/dns"
	"github.com/daeuniverse/dae/component/outbound"
	"github.com/daeuniverse/dae/component/outbound/dialer"
	"github.com/daeuniverse/dae/config"
	"github.com/daeuniverse/dae/pkg/logger/fastlog"
	"github.com/daeuniverse/outbound/pkg/fastrand"
	"github.com/daeuniverse/outbound/pool"
	dnsmessage "github.com/miekg/dns"
	log "github.com/sirupsen/logrus"
)

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
	ClearLookupCache   func() error
	BestDialerChooser  func(req *dnsRequest, upstream *dns.Upstream, outArg *dialArgument) error
	IpVersionPrefer    int
	FixedDomainTtl     map[string]int
	MinSniffingTtl     time.Duration
	EnableCache        bool
	SniffVerifyMode    consts.SniffVerifyMode
}

type coreIpDomainCacheValue struct {
	ip     netip.Addr
	bitmap *[32]uint32
}

type DnsController struct {
	routing     *dns.Dns
	qtypePrefer uint16

	matchBitmap        func(fqdn string, bitmap []uint32)
	newLookupCache     func(ip netip.Addr, domainBitmap *[32]uint32) error
	lookupCacheTimeout func(ip netip.Addr, domainBitmap *[32]uint32) error
	clearLookupCache   func() error
	bestDialerChooser  func(req *dnsRequest, upstream *dns.Upstream, outArg *dialArgument) error

	fixedDomainTtl     map[string]int
	minSniffingTtl     time.Duration
	enableCache        bool
	dnsCache           *commonDnsCache
	dnsCacheHashSeed   maphash.Seed
	dnsForwarderCache  sync.Map // map[dnsForwarderKey]DnsForwarder
	requestSelectCache *common.TimeWheelCache[HashKey, consts.DnsRequestOutboundIndex]
	coreIpDomainCache  *common.TimeWheelCache[HashKey, coreIpDomainCacheValue] // Key: Hash by qname + ip
	sniffDomainCache   *common.TimeWheelCache[HashKey, struct{}]               // Key: Loose mode hashes by qname; Strict mode hashes by qname+ip. Used by VerifySniff.
	sniffVerifyMode    consts.SniffVerifyMode

	// bitmapIntern canonicalizes domain match bitmaps by content: domains with
	// an identical match result (e.g. every geosite:cn-only domain) share one
	// *[32]uint32. Cleared on routing reload; patterns are tied to the matcher.
	bitmapInternMu sync.Mutex
	bitmapIntern   map[[32]uint32]*[32]uint32

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
		clearLookupCache:   option.ClearLookupCache,
		bestDialerChooser:  option.BestDialerChooser,

		fixedDomainTtl:     option.FixedDomainTtl,
		minSniffingTtl:     option.MinSniffingTtl,
		enableCache:        option.EnableCache,
		sniffVerifyMode:    option.SniffVerifyMode,
		dnsForwarderCache:  sync.Map{},
		dnsCache:           NewCommonDnsCache(),
		dnsCacheHashSeed:   maphash.MakeSeed(),
		requestSelectCache: common.NewTimeWheelCache[HashKey, consts.DnsRequestOutboundIndex](1*time.Hour, 5*time.Second, nil),
		sniffDomainCache:   common.NewTimeWheelCache[HashKey, struct{}](1*time.Hour, 5*time.Second, nil),
		bitmapIntern:       make(map[[32]uint32]*[32]uint32),
	}
	c.coreIpDomainCache = common.NewTimeWheelCache(
		1*time.Hour, 5*time.Second, func(_ HashKey, v coreIpDomainCacheValue, replaced bool) {
			if !replaced {
				c.recycleLookupCache(v.ip, v.bitmap)
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
	if err != nil || !dnsResponse(dataToWrite) {
		isNetError, _, _, isTemporary := GetNetErrorInfo(err)
		if !isNetError || !isTemporary {
			log.Errorf("%+v", err)
		}
		dataToWrite = data
		dnsRcodeSet(dataToWrite, dnsmessage.RcodeServerFailure)
	}
	// Keep the id the same with request.
	dnsIdSet(dataToWrite, id)

	// Truncate oversized UDP DNS responses with TC bit set (RFC 1035)
	// so the client retries over TCP. The function reads the client's
	// EDNS0 size from the request bytes and truncates only when needed.
	if !req.isTcp {
		dataToWrite = truncateDNSResponse(data, dataToWrite)
	}

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
		// Reject AAAA queries before forwarding when the selected dialer
		// cannot proxy IPv6 (determined by the initial connectivity check).
		// We build a fresh response buffer instead of mutating `data` in
		// place because the race path shares `data` across goroutines.
		if queryInfo.qtype == dnsmessage.TypeAAAA &&
			dialArgument.Dialer != nil && dialArgument.Dialer.NoIpv6() {
			if log.IsLevelEnabled(log.DebugLevel) {
				log.WithFields(log.Fields{
					"qname":    queryInfo.qname,
					"dialer":   dialArgument.Dialer.Name,
					"upstream": upstream.String(),
				}).Debugln("Reject AAAA query: dialer cannot proxy IPv6")
			}
			respData := pool.GetBuffer(len(data))
			copy(respData, data)
			c.reject(respData)
			dnsResp.respData = respData
			dnsResp.fromPool = true
			dnsResp.isNew = false
			return nil
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
		ips, ttl := dnsAnswers(dnsResp.respData)
		// SniffVerifyMode_None never uses sniffDomainCache — skip entirely.
		if len(ips) > 0 && c.sniffVerifyMode != consts.SniffVerifyMode_None {
			qHash := c.QnameHash(queryInfo.qname)
			lookupTTL := max(time.Duration(ttl)*time.Second, c.minSniffingTtl)
			switch c.sniffVerifyMode {
			case consts.SniffVerifyMode_Loose:
				// Loose mode: key by qname only; existence signals "was resolved".
				c.sniffDomainCache.SaveWithTTL(qHash, struct{}{}, lookupTTL)
			case consts.SniffVerifyMode_Strict:
				// Strict mode: key by qname+ip for per-IP exact matching.
				for _, ip := range ips {
					c.sniffDomainCache.SaveWithTTL(QnameIpHash(qHash, ip), struct{}{}, lookupTTL)
				}
			}
		}
		// Update eBPF lookup cache. Always register the domain — even when its
		// bitmap is all zero — so domainStates[ip].total counts every cached
		// domain and the domain_routing_map invariant (matched[i] == total)
		// stays correct (see computeDomainBitmaps).
		domainBitmap := common.ObtainDomainBitmap()
		defer common.RecycleDomainBitmap(domainBitmap)
		c.matchBitmap(queryInfo.qname, domainBitmap)
		err = c.updateLookupCache(queryInfo.qname, domainBitmap, ips, time.Duration(ttl)*time.Second)
	}
	return err
}

// ResolveForVerification triggers a real DNS query through DAE's full DNS pipeline
// (routing, upstream selection, forwarding, caching, and eBPF domain sync).
// It is used by VerifySniff as the slow path when sniffDomainCache misses,
// replacing the old netutils.ResolveIp46 which bypassed DAE and leaked DNS.
func (c *DnsController) ResolveForVerification(fqdn string, src netip.AddrPort, routingResult *bpfRoutingResult) (ok bool) {
	// fqdn may be an IP literal (e.g. from SNI when connecting to an IP
	// directly). Skip DNS lookup — IPs don't have A/AAAA records.
	if _, err := netip.ParseAddr(strings.TrimSuffix(fqdn, ".")); err == nil {
		return false
	}

	dataBuf := pool.GetBuffer(consts.EthernetMtu)
	defer pool.PutBuffer(dataBuf)
	// Try A first; if it resolves, skip AAAA. Verification only needs to
	// confirm the domain has DNS records — one record type is sufficient.
	for _, qtype := range []uint16{dnsmessage.TypeA, dnsmessage.TypeAAAA} {
		msg := new(dnsmessage.Msg)
		msg.SetQuestion(dnsmessage.Fqdn(fqdn), qtype)
		msg.RecursionDesired = true
		data, packErr := msg.PackBuffer(dataBuf)
		if packErr != nil {
			log.WithField("qname", fqdn).WithField("qtype", qtype).
				Errorf("ResolveForVerification: failed to pack DNS message: %v", packErr)
			return false
		}

		// handleDNSRequest handles routing (RequestSelect, race groups),
		// upstream resolution, forwarding, and auto-populates
		// sniffDomainCache, dnsCache, lookupCache, coreIpDomainCache,
		// and eBPF maps.
		dnsResp := dnsResponseDataPool.Get().(*dnsResponseData)
		// Dst is only used in case of ASIS, hard-code localhost:53 here.
		req := ObtainDnsRequest(src, netip.MustParseAddrPort("127.0.0.1:53"), routingResult, false)
		qi := queryInfo{qname: fqdn, qtype: qtype}
		pipeErr := c.handleDNSRequest(data, req, qi, dnsResp)
		RecycleDnsRequest(req)
		if pipeErr != nil {
			log.WithField("qname", fqdn).WithField("qtype", qtype).
				Warnf("ResolveForVerification: %v", pipeErr)
		} else {
			resolvedIps, _ := dnsAnswers(dnsResp.respData)
			if len(resolvedIps) == 0 {
				log.WithField("qname", fqdn).WithField("qtype", qtype).
					Warnf("ResolveForVerification: no IPs resolved")
				pipeErr = io.EOF // Sasify the nil check below.
			}
		}
		if dnsResp.respData != nil && dnsResp.fromPool {
			pool.PutBuffer(dnsResp.respData)
		}
		*dnsResp = dnsResponseData{}
		dnsResponseDataPool.Put(dnsResp)
		if pipeErr == nil {
			return true
		}
	}
	return false
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
	var winner atomic.Bool
	type result struct {
		err error
		win bool
	}
	ch := make(chan result, len(raceUpstreams))

	for _, upstream := range raceUpstreams {
		go func(upstream *dns.Upstream) {
			localResp := dnsResponseDataPool.Get().(*dnsResponseData)
			err := c.handleDNSRequestByUpstream(data, req, queryInfo, upstream, localResp)
			win := err == nil && winner.CompareAndSwap(false, true)
			if win {
				*dnsResp = *localResp
			} else if localResp.respData != nil && localResp.fromPool {
				pool.PutBuffer(localResp.respData)
			}
			*localResp = dnsResponseData{}
			dnsResponseDataPool.Put(localResp)
			ch <- result{err: err, win: win}
		}(upstream)
	}

	var firstErr error
	for range len(raceUpstreams) {
		if res := <-ch; res.win {
			return nil
		} else if firstErr == nil && res.err != nil {
			firstErr = res.err
		}
	}
	return fmt.Errorf("all %d race upstreams failed: %w", len(raceUpstreams), firstErr)
}

func (c *DnsController) logDnsResponse(req *dnsRequest, dialArgument *dialArgument, queryInfo queryInfo, accepted bool) {
	if !log.IsLevelEnabled(log.InfoLevel) || !fastlog.Enabled() {
		return
	}

	fastlog.LogDnsResponse(
		req.Src, req.Dst,
		req.isTcp,
		dialArgument.Target,
		dialArgument.networkType.String(),
		dialArgument.Outbound.Name,
		string(dialArgument.Outbound.GetSelectionPolicy()),
		dialArgument.Dialer.Name,
		queryInfo.qname,
		queryInfo.qtype,
		req.routingResult.Pname,
		req.routingResult.Mac,
		req.routingResult.Pid,
		req.routingResult.Ifindex,
		req.routingResult.Dscp,
		accepted,
	)
}

func (c *DnsController) isDomainBitmapAllZero(qname string, domainBitmap []uint32) bool {
	if domainBitmap == nil {
		domainBitmap = common.ObtainDomainBitmap()
		defer common.RecycleDomainBitmap(domainBitmap)
	}
	c.matchBitmap(qname, domainBitmap)
	for _, v := range domainBitmap {
		if v != 0 {
			return false
		}
	}
	return true
}

// zeroDomainBitmap is a shared, immutable all-zero bitmap used for domains
// that match no routing rule, avoiding a 256-byte allocation per such domain.
var zeroDomainBitmap = new([32]uint32)

func isBitmapZero(bitmap []uint32) bool {
	for _, v := range bitmap {
		if v != 0 {
			return false
		}
	}
	return true
}

// internBitmap returns a canonical, immutable *[32]uint32 for the given match
// bitmap. All-zero bitmaps share zeroDomainBitmap; identical non-zero bitmaps
// share one canonical array, so e.g. every geosite:cn-only domain points at
// the same 128 bytes.
func (c *DnsController) internBitmap(bitmap []uint32) *[32]uint32 {
	if isBitmapZero(bitmap) {
		return zeroDomainBitmap
	}
	// Reinterpret the 32-word slice as an array pointer (zero-copy; the slice
	// is always length 32). The map hashes/compares the array in place.
	key := (*[32]uint32)(bitmap)
	c.bitmapInternMu.Lock()
	defer c.bitmapInternMu.Unlock()
	if p, ok := c.bitmapIntern[*key]; ok {
		return p
	}
	p := new([32]uint32)
	copy(p[:], bitmap)
	c.bitmapIntern[*key] = p
	common.Metrics.CoreBitmapCount.With0().Inc()
	return p
}

func (c *DnsController) updateLookupCache(qname string, domainBitmap []uint32, ips []netip.Addr, ttl time.Duration) error {
	if len(ips) == 0 {
		return nil
	}
	lookupTTL := max(ttl, c.minSniffingTtl)
	// Avoid caching bytes from pool.
	var bitmapToCache *[32]uint32

	qHash := c.QnameHash(qname)

	for _, ip := range ips {
		hashKey := QnameIpHash(qHash, ip)
		if v, ok := c.coreIpDomainCache.Get(hashKey); ok {
			// Just update ttl, no need to update ebpf map.
			c.coreIpDomainCache.SaveWithTTL(hashKey, v, lookupTTL)
			continue
		}
		if bitmapToCache == nil {
			bitmapToCache = c.internBitmap(domainBitmap)
		}
		go newLookupCacheAsync(c, ip, bitmapToCache)
		c.coreIpDomainCache.SaveWithTTL(hashKey, coreIpDomainCacheValue{ip: ip, bitmap: bitmapToCache}, lookupTTL)
		common.Metrics.CoreIpDomainBitmap.With0().Inc()
	}
	return nil
}

func (c *DnsController) recycleLookupCache(ip netip.Addr, bitmap *[32]uint32) {
	go lookupCacheTimeoutAsync(c, ip, bitmap)
	common.Metrics.CoreIpDomainBitmap.With0().Dec()
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
	c.matchBitmap(qname, domainBitmap)
	return c.updateLookupCache(qname, domainBitmap, ips, ttl)
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
		if r == nil {
			return nil, fmt.Errorf("empty DNS response from %v", upstream.String())
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
	if err != nil {
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
	c.dnsCache.Range(func(_ HashKey, cache *dnsCache, _ time.Duration) bool {
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

// ReplayDomainBitmaps rebuilds the (ip, bitmap) state from the DNS response
// cache after a routing change. The coreIpDomainCache no longer stores the
// qname (it only keeps ip + bitmap), so instead of recomputing per-entry it
// clears the derived state and re-registers every domain found in the still
// intact commonDnsCache. matchBitmap must be backed by the new matcher.
//
// Note: commonDnsCache (1h) is shorter-lived than the bitmap state
// (min_sniffing_ttl, default up to 24h), so domains resolved longer ago than
// the DNS cache TTL are dropped here and re-register on their next resolution.
func (c *DnsController) ReplayDomainBitmaps(matchBitmap func(fqdn string, bitmap []uint32)) {
	// Clear the derived (ip, bitmap) state: the in-userspace cache, the per-IP
	// eBPF state, the metric, and the bitmap intern table (patterns are tied
	// to the routing rules, which just changed).
	c.coreIpDomainCache.Clear()
	common.Metrics.CoreIpDomainBitmap.Reset()
	common.Metrics.CoreBitmapCount.Reset()
	c.bitmapInternMu.Lock()
	c.bitmapIntern = make(map[[32]uint32]*[32]uint32)
	c.bitmapInternMu.Unlock()
	if c.clearLookupCache != nil {
		if err := c.clearLookupCache(); err != nil {
			log.WithError(err).Warn("ReplayDomainBitmaps: failed to clear domain state")
		}
	}

	// Rebuild by scanning the raw DNS responses.
	c.dnsCache.Range(func(_ HashKey, cache *dnsCache, ttl time.Duration) bool {
		qname, _, ok := dnsQuestion(cache.Data)
		if !ok {
			return true
		}
		ips, _ := dnsAnswers(cache.Data)
		if len(ips) == 0 {
			return true
		}
		bitmap := common.ObtainDomainBitmap()
		matchBitmap(qname, bitmap)
		if err := c.updateLookupCache(qname, bitmap, ips, ttl); err != nil {
			log.WithField("qname", qname).WithField("err", err).
				Warn("ReplayDomainBitmaps: failed to re-register domain")
		}
		common.RecycleDomainBitmap(bitmap)
		return true
	})
}

// TransferDomainState moves all domain cache entries from c to dst so
// that the BPF domain maps stay in sync with the surviving controller.
// Called from UpdateDns() before the old DnsController is closed.
func (c *DnsController) TransferDomainState(dst *DnsController) {
	// Transfer all coreIpDomainCache entries.
	c.coreIpDomainCache.Range(func(key HashKey, v coreIpDomainCacheValue, ttl time.Duration) bool {
		dst.coreIpDomainCache.SaveWithTTL(key, v, ttl)
		return true
	})
	c.coreIpDomainCache.Close()
	c.coreIpDomainCache = nil
}

func (c *DnsController) Close() error {
	// Release interned domain-matcher structures shared with other matchers.
	if c.routing != nil {
		c.routing.Release()
	}

	c.requestSelectCache.Close()
	c.dnsCache.Close()

	// Clean up cache & deadline timers.
	if c.coreIpDomainCache != nil {
		c.coreIpDomainCache.Close()
	}

	// Close all DNS forwarders
	c.dnsForwarderCache.Range(func(key, value any) bool {
		if forwarder, ok := value.(io.Closer); ok {
			forwarder.Close()
		}
		return true
	})
	return nil
}
