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
	BestDialerChooser  func(req *dnsRequest, upstream *dns.Upstream, outArg *dialArgument) error
	IpVersionPrefer    int
	FixedDomainTtl     map[string]int
	MinSniffingTtl     time.Duration
	EnableCache        bool
	SniffVerifyMode    consts.SniffVerifyMode
}

type coreIpDomainCacheValue struct {
	qHash  HashKey
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
	coreIpDomainCache  *common.TimeWheelCache[HashKey, coreIpDomainCacheValue] // Key: Hash by qname + ip
	sniffDomainCache   *common.TimeWheelCache[HashKey, struct{}]               // Key: Loose mode hashes by qname; Strict mode hashes by qname+ip. Used by VerifySniff.
	sniffVerifyMode    consts.SniffVerifyMode

	singleFlightGroup common.SingleFlight[HashKey, *dnsmessage.Msg, singleFlightParam]
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
		dnsCache:           newCommonDnsCache(),
		dnsCacheHashSeed:   maphash.MakeSeed(),
		requestSelectCache: common.NewTimeWheelCache[HashKey, consts.DnsRequestOutboundIndex](1*time.Hour, 5*time.Second, nil),
		sniffDomainCache:   common.NewTimeWheelCache[HashKey, struct{}](1*time.Hour, 5*time.Second, nil),
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
	c   *DnsController
	msg *dnsmessage.Msg
	qi  queryInfo
}

type dnsForwarderKey struct {
	upstream     dns.Upstream
	dialArgument dialArgument
}

type queryInfo struct {
	qname string
	qtype uint16
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

func (c *DnsController) prepareQueryInfo(dnsMessage *dnsmessage.Msg) (queryInfo queryInfo) {
	if len(dnsMessage.Question) != 0 {
		q := dnsMessage.Question[0]
		queryInfo.qname = common.CanonicalName(q.Name)
		queryInfo.qtype = q.Qtype
	}
	return
}

func (c *DnsController) Handle(dnsMessage *dnsmessage.Msg, req *dnsRequest) {
	if log.IsLevelEnabled(log.TraceLevel) && len(dnsMessage.Question) > 0 {
		q := dnsMessage.Question[0]
		log.Tracef("Received UDP(DNS) %v <-> %v: %v %v",
			RefineSourceToShow(req.Src, req.Dst.Addr()), req.Dst.String(), strings.ToLower(q.Name), QtypeToString(q.Qtype),
		)
	}

	if dnsMessage.Response {
		log.Errorln("DNS request expected but DNS response received")
	}

	queryInfo := c.prepareQueryInfo(dnsMessage)

	// qname is empty when dnsQuestion failed to parse the question section
	// (malformed packet, non-INET class, etc.). Return false so the data
	// falls through to regular UDP routing.
	if queryInfo.qname == "" {
		return
	}

	id := dnsMessage.Id
	// Avoids duplicated id from clients, so make the id unique.
	dnsMessage.Id = uint16(fastrand.Intn(math.MaxUint16))

	var err error
	// Check ip version preference and qtype.
	switch queryInfo.qtype {
	case dnsmessage.TypeA, dnsmessage.TypeAAAA:
		if c.qtypePrefer == 0 {
			err = c.handleDNSRequest(dnsMessage, req, queryInfo)
		} else {
			// Try to make both A and AAAA lookups.
			dnsMessage2 := dnsMessage.Copy()
			dnsMessage2.Id = uint16(fastrand.Intn(math.MaxUint16))
			switch queryInfo.qtype {
			case dnsmessage.TypeA:
				dnsMessage2.Question[0].Qtype = dnsmessage.TypeAAAA
			case dnsmessage.TypeAAAA:
				dnsMessage2.Question[0].Qtype = dnsmessage.TypeA
			}

			errCh := make(chan error, 1)
			go func() {
				err = c.handleDNSRequest(dnsMessage2, req, queryInfo)
				errCh <- err
			}()
			err = common.Join(c.handleDNSRequest(dnsMessage, req, queryInfo), <-errCh)
			if err != nil {
				break
			}
			if c.qtypePrefer != queryInfo.qtype && dnsMessage2 != nil && IncludeAnyIpInMsg(dnsMessage2) {
				c.reject(dnsMessage)
			}
		}
	default:
		err = c.handleDNSRequest(dnsMessage, req, queryInfo)
	}
	if err != nil {
		isNetError, _, _, isTemporary := GetNetErrorInfo(err)
		if !isNetError || !isTemporary {
			log.Warningf("%+v", err)
		}
		dnsMessage.Rcode = dnsmessage.RcodeServerFailure
		dnsMessage.Response = true
	}
	// Keep the id the same with request.
	dnsMessage.Id = id
	dnsMessage.Compress = true
	buf := pool.GetBuffer(512)
	defer pool.PutBuffer(buf)
	data, err := dnsMessage.PackBuffer(buf)
	if err != nil {
		log.Errorf("%+v", common.Wrap(err, "failed to pack dns message"))
		return
	}

	// Send back the dns response.
	af, err := DefaultAnyfromPool.Obtain(req.Dst, AnyfromTimeoutDefault)
	if err == nil {
		_, err = af.WriteToUDPAddrPort(data, req.Src)
		DefaultAnyfromPool.Recycle(req.Dst, af)
	}
	if err != nil {
		log.Warningf("failed to send dns message back: %v", err)
	}
}

func (c *DnsController) handleDNSRequest(
	dnsMessage *dnsmessage.Msg,
	req *dnsRequest,
	queryInfo queryInfo,
) error {
	// Route Request
	hashKey := c.GetHashKey(queryInfo.qname, queryInfo.qtype, nil, nil)
	RequestIndex, ok := c.requestSelectCache.Get(hashKey)
	if !ok {
		var err error
		RequestIndex, err = c.routing.RequestSelect(queryInfo.qname, queryInfo.qtype)
		if err != nil {
			return err
		}
		c.requestSelectCache.Save(hashKey, RequestIndex)
	}

	if RequestIndex == consts.DnsRequestOutboundIndex_Reject {
		c.reject(dnsMessage)
		return nil
	}

	// Check for race group: race(upstream1, upstream2, ...)
	if raceUpstreams := c.routing.GetRaceUpstreams(RequestIndex); len(raceUpstreams) > 0 {
		return c.handleDNSRequestRace(dnsMessage, req, queryInfo, raceUpstreams)
	}

	// Resolve the single upstream and dial.
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
		var err error
		upstream, err = c.routing.GetUpstream(RequestIndex)
		if err != nil {
			return err
		}
	}

	return c.handleDNSRequestByUpstream(dnsMessage, req, queryInfo, upstream)
}

// handleDNSRequestByUpstream selects the best dialer, sends DNS query, handles response
// routing, logging, and lookup cache update. It manages dialArgument lifecycle internally.
// The dnsMessage is modified in-place by dialSend and response routing.
func (c *DnsController) handleDNSRequestByUpstream(
	dnsMessage *dnsmessage.Msg,
	req *dnsRequest,
	queryInfo queryInfo,
	upstream *dns.Upstream,
) error {
	dialArgument := dialArgumentPool.Get().(*dialArgument)
	defer dialArgumentPool.Put(dialArgument)

	var isNew bool
	var reqMsg *dnsmessage.Msg
	if !c.routing.HasResponseRules() {
		reqMsg = dnsMessage
	} else {
		reqMsg = dnsMessage.Copy()
	}

	var err error
Dial:
	for invokingDepth := 1; invokingDepth <= MaxDnsLookupDepth; invokingDepth++ {
		if log.IsLevelEnabled(log.DebugLevel) {
			log.WithFields(log.Fields{
				"question": dnsMessage.Question,
				"upstream": upstream.String(),
			}).Debugln("Request to DNS upstream")
		}

		// Select best dial arguments and send DNS query.
		if err = c.bestDialerChooser(req, upstream, dialArgument); err != nil {
			return err
		}
		isNew, err = c.dialSend(dnsMessage, upstream, dialArgument, queryInfo)
		if err != nil {
			isNetError, isClosed, isTimeout, isTemporary := GetNetErrorInfo(err)
			if !isNetError || isClosed || !dnsMessage.Response || (!isTimeout && dialArgument.Dialer.NeedAliveState()) {
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
				if !isNetError || isClosed || !dnsMessage.Response {
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
		// Route response.
		ResponseIndex, nextUpstream, err := c.routing.ResponseSelect(dnsMessage, upstream)
		if err != nil {
			return err
		}
		if ResponseIndex.IsReserved() {
			c.logDnsResponse(req, dialArgument, queryInfo, ResponseIndex == consts.DnsResponseOutboundIndex_Accept)
			switch ResponseIndex {
			case consts.DnsResponseOutboundIndex_Reject:
				c.reject(dnsMessage)
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
				"question":      dnsMessage.Question,
				"last_upstream": upstream.String(),
				"next_upstream": nextUpstream.String(),
			}).Debugln("Change DNS upstream and resend")
		}
		upstream = nextUpstream
		reqMsg.CopyTo(dnsMessage)
	}
	// Update lookup cache.
	switch {
	case !dnsMessage.Response,
		len(dnsMessage.Answer) == 0,
		len(dnsMessage.Question) == 0,               // Check healthy resp.
		dnsMessage.Rcode != dnsmessage.RcodeSuccess: // Check suc resp.
		return nil
	}
	if isNew {
		var ttl uint32
		var ips []netip.Addr
		for _, rr := range dnsMessage.Answer {
			if ttl == 0 {
				ttl = rr.Header().Ttl
			}
			ip, ok := GetIp(rr)
			if ok {
				ips = append(ips, ip)
			}
		}
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
		// Update eBPF lookup cache.
		domainBitmap := common.ObtainDomainBitmap()
		defer common.RecycleDomainBitmap(domainBitmap)
		if !c.isDomainBitmapAllZero(queryInfo.qname, domainBitmap) {
			return c.updateLookupCache(queryInfo.qname, domainBitmap, ips, time.Duration(ttl)*time.Second)
		}
	}
	return nil
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

	// Try A first; if it resolves, skip AAAA. Verification only needs to
	// confirm the domain has DNS records — one record type is sufficient.
	for _, qtype := range []uint16{dnsmessage.TypeA, dnsmessage.TypeAAAA} {
		msg := new(dnsmessage.Msg)
		msg.SetQuestion(dnsmessage.Fqdn(fqdn), qtype)
		msg.RecursionDesired = true

		// handleDNSRequest handles routing (RequestSelect, race groups),
		// upstream resolution, forwarding, and auto-populates
		// sniffDomainCache, dnsCache, lookupCache, coreIpDomainCache,
		// and eBPF maps.
		// Dst is only used in case of ASIS, hard-code localhost:53 here.
		req := ObtainDnsRequest(src, netip.MustParseAddrPort("127.0.0.1:53"), routingResult, false)
		qi := queryInfo{qname: fqdn, qtype: qtype}
		pipeErr := c.handleDNSRequest(msg, req, qi)
		RecycleDnsRequest(req)
		if pipeErr != nil {
			log.WithField("qname", fqdn).WithField("qtype", qtype).
				Warnf("ResolveForVerification: %v", pipeErr)
			continue
		}
		for _, rr := range msg.Answer {
			if _, ok := GetIp(rr); ok {
				return true
			}
		}
		log.WithField("qname", fqdn).WithField("qtype", qtype).
			Warnf("ResolveForVerification: no IPs resolved")
	}
	return false
}

// handleDNSRequestRace sends DNS queries to multiple upstreams concurrently and uses the
// first successful response. Each sub-upstream independently goes through the full
// handleDNSRequestByUpstream path (including response routing).
func (c *DnsController) handleDNSRequestRace(
	dnsMessage *dnsmessage.Msg,
	req *dnsRequest,
	queryInfo queryInfo,
	raceUpstreams []*dns.Upstream,
) error {
	var winner atomic.Bool
	type result struct {
		err error
		win bool
	}
	ch := make(chan result, len(raceUpstreams))

	for _, upstream := range raceUpstreams {
		go func(upstream *dns.Upstream, msg *dnsmessage.Msg) {
			err := c.handleDNSRequestByUpstream(msg, req, queryInfo, upstream)
			win := err == nil && msg.Response && len(msg.Answer) > 0 && winner.CompareAndSwap(false, true)
			if win {
				msg.CopyTo(dnsMessage)
			}
			ch <- result{err: err, win: win}
		}(upstream, dnsMessage.Copy())
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

func (c *DnsController) updateLookupCache(qname string, domainBitmap []uint32, ips []netip.Addr, ttl time.Duration) error {
	if len(ips) == 0 {
		return nil
	}
	lookupTTL := max(ttl, c.minSniffingTtl)
	bitmap := (*[32]uint32)(domainBitmap)

	qHash := c.QnameHash(qname)

	for _, ip := range ips {
		hashKey := QnameIpHash(qHash, ip)
		if v, ok := c.coreIpDomainCache.Get(hashKey); ok {
			// Just update ttl, no need to update ebpf map.
			c.coreIpDomainCache.SaveWithTTL(hashKey, v, lookupTTL)
			continue
		}
		go newLookupCacheAsync(c, ip, bitmap)
		c.coreIpDomainCache.SaveWithTTL(hashKey, coreIpDomainCacheValue{qHash: qHash, qname: qname, ip: ip, bitmap: bitmap}, lookupTTL)
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
	if !c.isDomainBitmapAllZero(qname, domainBitmap) {
		return c.updateLookupCache(qname, domainBitmap, ips, ttl)
	}
	return nil
}

func (c *DnsController) reject(msg *dnsmessage.Msg) {
	// Reject with empty answer.
	msg.Answer = []dnsmessage.RR{}
	msg.Rcode = dnsmessage.RcodeSuccess
	msg.Response = true
	msg.RecursionAvailable = true
	msg.Truncated = false
}

type dnsRefreshParam struct {
	data     *dnsmessage.Msg
	qi       queryInfo
	upstream *dns.Upstream
	dialArg  dialArgument
}

var dnsRefreshParamPool = sync.Pool{
	New: func() any { return &dnsRefreshParam{} },
}

func obtainDnsRefreshParam(data *dnsmessage.Msg, qi queryInfo, upstream *dns.Upstream, dialArg *dialArgument) *dnsRefreshParam {
	p := dnsRefreshParamPool.Get().(*dnsRefreshParam)
	p.data = data
	p.qi = qi
	p.upstream = upstream
	p.dialArg = *dialArg
	return p
}

func recycleDnsRefreshParam(p *dnsRefreshParam) {
	p.data = nil
	p.upstream = nil
	p.qi = queryInfo{}
	p.dialArg = dialArgument{}
	dnsRefreshParamPool.Put(p)
}

func (c *DnsController) dialSend(msg *dnsmessage.Msg, upstream *dns.Upstream, dialArg *dialArgument, queryInfo queryInfo) (bool, error) {
	// Lookup Cache
	if c.enableCache {
		if rr, fetchedAt, isNew := c.dnsCache.Get(c.GetHashKey(queryInfo.qname, queryInfo.qtype, dialArg.Outbound, dialArg.Dialer)); rr != nil {
			originalMsgForExpiredFetch := FillMsgByCache(msg, rr, fetchedAt)
			if originalMsgForExpiredFetch != nil {
				// Refresh cache asynchronously.
				go func(c *DnsController, p *dnsRefreshParam) {
					defer recycleDnsRefreshParam(p)
					if _, err := c.singleFlightForwardDNS(p.qi, p.data, p.upstream, &p.dialArg); err != nil {
						log.Warnf("failed to refresh dns cache for %v: %+v", p.qi, err)
					}
				}(c, obtainDnsRefreshParam(originalMsgForExpiredFetch, queryInfo, upstream, dialArg))
			}
			if log.IsLevelEnabled(log.DebugLevel) && len(msg.Question) > 0 {
				log.WithFields(log.Fields{
					"answer": msg.Answer,
				}).Debugf("UDP(DNS) <-> Cache: %v %v", queryInfo.qname, queryInfo.qtype)
			}
			return isNew, nil
		}
	}
	// Pending for the same lookup.
	msgResp, err := c.singleFlightForwardDNS(queryInfo, msg, upstream, dialArg)
	if err == nil && msgResp != nil && msgResp != msg {
		// Only copy necessary response fields. Note: the msg.Id may be changing in the first goroutine.
		msg.Response = true
		msg.Rcode = msgResp.Rcode
		msg.RecursionAvailable = msgResp.RecursionAvailable
		msg.Truncated = msgResp.Truncated
		msg.Authoritative = msgResp.Authoritative
		msg.AuthenticatedData = msgResp.AuthenticatedData
		// The answers should have been saved to cache and won't be modified afterwards.
		msg.Answer = msgResp.Answer
		msg.Ns = msgResp.Ns
		msg.Extra = msgResp.Extra
	}
	return true, err
}

func (c *DnsController) singleFlightForwardDNS(
	qi queryInfo, msg *dnsmessage.Msg, upstream *dns.Upstream, dialArgument *dialArgument) (*dnsmessage.Msg, error) {
	hashKey := c.GetHashKey(qi.qname, qi.qtype, dialArgument.Outbound, dialArgument.Dialer)
	param := singleFlightParam{
		dnsForwarderKey: dnsForwarderKey{upstream: *upstream, dialArgument: *dialArgument},
		c:               c,
		msg:             msg,
		qi:              qi,
	}
	resp, err, _, _ := c.singleFlightGroup.Do(hashKey, param, func(p singleFlightParam) (*dnsmessage.Msg, error) {
		forwarderKey := p.dnsForwarderKey
		upstream := forwarderKey.upstream
		dialArgument := forwarderKey.dialArgument
		c := p.c
		msg := p.msg
		qname := p.qi.qname
		qtype := p.qi.qtype

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

		err := forwarder.ForwardDNS(msg)
		if err != nil {
			return nil, err
		}
		// Check suc resp.
		if len(msg.Question) == 0 || msg.Rcode != dnsmessage.RcodeSuccess {
			if log.IsLevelEnabled(log.DebugLevel) {
				log.WithFields(log.Fields{
					"qname": qname,
					"qtype": qtype,
					"rcode": msg.Rcode,
					"ans":   FormatDnsRsc(msg.Answer),
				}).Debugf("Not a valid DNS response")
			}
		} else if c.enableCache && shouldSaveToCache(&upstream, qname) {
			// Skip cache for static entries to allow dynamic updates
			if log.IsLevelEnabled(log.DebugLevel) {
				log.WithFields(log.Fields{
					"qname":    qname,
					"qtype":    qtype,
					"rcode":    msg.Rcode,
					"ans":      FormatDnsRsc(msg.Answer),
					"upstream": upstream,
					"dialer":   dialArgument.Dialer,
					"outbound": dialArgument.Outbound,
				}).Debugf("Update DNS record cache")
			}
			key := c.GetHashKey(qname, qtype, dialArgument.Outbound, dialArgument.Dialer)
			fixedTtl := c.fixedDomainTtl[qname]
			c.dnsCache.Save(key, msg.Answer, fixedTtl)
		}
		return msg, nil
	})
	if err != nil {
		return nil, err
	}
	if !resp.Response {
		return nil, common.Errf("DNS message response flag is unset")
	}
	return resp, nil
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

// ReplayDomainBitmaps recomputes the routing bitmap for every cached
// (domain, IP) pair using the supplied matchBitmap callback, which should
// be backed by the new routing matcher. On mismatch the BPF domain maps
// are updated and the cache entry rewritten. Called from UpdateRouting()
// to correct domain routing state without purging DNS data.
func (c *DnsController) ReplayDomainBitmaps(matchBitmap func(fqdn string, bitmap []uint32)) {
	// Collect entries whose bitmap changed; SaveWithTTL takes the cache
	// write-lock, which must not be called inside Range (which holds RLock).
	type updateEntry struct {
		key HashKey
		val coreIpDomainCacheValue
		ttl time.Duration
	}
	updates := make([]updateEntry, 0, 16)

	c.coreIpDomainCache.Range(func(key HashKey, v coreIpDomainCacheValue, ttl time.Duration) bool {
		if v.qname == "" || v.bitmap == nil {
			return true
		}
		oldBitmap := v.bitmap
		newSlice := common.ObtainDomainBitmap()
		matchBitmap(v.qname, newSlice)
		newBitmap := (*[32]uint32)(newSlice)

		if *oldBitmap == *newBitmap {
			common.RecycleDomainBitmap(newSlice)
			return true
		}

		// Remove old BPF entries, add new ones.
		if err := c.lookupCacheTimeout(v.ip, oldBitmap); err != nil {
			log.WithField("ip", v.ip).WithField("err", err).
				Warn("ReplayDomainBitmaps: failed to remove old domain state")
		}
		allZero := true
		for _, w := range newBitmap {
			if w != 0 {
				allZero = false
				break
			}
		}
		if !allZero {
			if err := c.newLookupCache(v.ip, newBitmap); err != nil {
				log.WithField("ip", v.ip).WithField("err", err).
					Warn("ReplayDomainBitmaps: failed to add new domain state")
			}
		}
		updates = append(updates, updateEntry{
			key: key,
			val: coreIpDomainCacheValue{
				qHash:  v.qHash,
				qname:  v.qname,
				ip:     v.ip,
				bitmap: newBitmap,
			},
			ttl: ttl,
		})
		return true
	})

	for _, entry := range updates {
		c.coreIpDomainCache.SaveWithTTL(entry.key, entry.val, entry.ttl)
	}
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
