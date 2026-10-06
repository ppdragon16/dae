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
	// ErrDnsForwardersClosed is returned when a forwarder is requested
	// after the controller's forwarder cache has been swept by Close.
	// In-flight queries that outlived the close handle-gate must fail
	// instead of repopulating forwarders nothing will ever close again.
	ErrDnsForwardersClosed = fmt.Errorf("dns forwarder cache is closed")
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
	// EcsDefault is the global dns.ecs policy ("strip"/"pass"),
	// already validated by ParseEcsDefault. Nil means pass-through.
	EcsDefault string
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

	fixedDomainTtl   map[string]int
	minSniffingTtl   time.Duration
	enableCache      bool
	dnsCache         *commonDnsCache
	dnsCacheHashSeed maphash.Seed
	// dnsForwardersClosed is set before Close sweeps the forwarder cache.
	// getOrCreate re-checks it after a store so an in-flight query that
	// outlived the close handle-gate cannot repopulate a forwarder that
	// nothing will ever sweep or close again.
	dnsForwardersClosed atomic.Bool
	dnsForwarderCache   sync.Map // map[dnsForwarderKey]DnsForwarder
	requestSelectCache  *common.TimeWheelCache[HashKey, consts.DnsRequestOutboundIndex]
	coreIpDomainCache   *common.TimeWheelCache[HashKey, coreIpDomainCacheValue] // Key: Hash by qname + ip
	sniffDomainCache    *common.TimeWheelCache[HashKey, struct{}]               // Key: Loose mode hashes by qname; Strict mode hashes by qname+ip. Used by VerifySniff.
	sniffVerifyMode     consts.SniffVerifyMode

	// ecsDefaultSpec is the effective dns.ecs default (validated at
	// construction). Per-dialer [ecs: ...] annotations override it;
	// nil means pass-through.
	ecsDefaultSpec *dialer.EcsSpec

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
		ecsDefaultSpec:     nil,
		dnsForwarderCache:  sync.Map{},
		dnsCache:           NewCommonDnsCache(),
		dnsCacheHashSeed:   maphash.MakeSeed(),
		requestSelectCache: common.NewTimeWheelCache[HashKey, consts.DnsRequestOutboundIndex](1*time.Hour, 5*time.Second, nil),
		sniffDomainCache:   common.NewTimeWheelCache[HashKey, struct{}](1*time.Hour, 5*time.Second, nil),
		bitmapIntern:       make(map[[32]uint32]*[32]uint32),
	}
	if c.ecsDefaultSpec, err = ParseEcsDefault(option.EcsDefault); err != nil {
		return nil, err
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

// mixDnsAnnotationKey folds the per-dialer annotation identity into the
// DNS cache key. Returns (mixed, isolated): isolated reports whether a
// dns_cache_tag domain was applied (callers stop mixing further keys).
// Dialers applying different ECS policies must not share cached answers
// either, so the canonical ECS key is mixed into both branches. With no
// annotations the key stays bit-identical to the legacy scheme.
// mixDnsAnnotationKey folds the per-dialer annotation identity and the
// effective ECS policy into the DNS cache key. Returns (mixed,
// isolated): isolated reports whether a dns_cache_tag domain was
// applied (callers stop mixing further keys). The annotation's ECS
// policy wins over the global default; dialers applying different ECS
// policies must not share cached answers, so the canonical ECS key is
// mixed into both branches. With no annotations and no global default
// the key stays bit-identical to the legacy scheme.
func mixDnsAnnotationKey(h1 uint64, seed maphash.Seed, anno *dialer.Annotation, ecsDefault *dialer.EcsSpec) (uint64, bool) {
	ecs := ecsDefault
	if anno != nil && anno.Ecs != nil {
		ecs = anno.Ecs
	}
	if ecs != nil {
		h1 ^= maphash.String(seed, ecs.Key)
	}
	if anno == nil {
		return h1, false
	}
	if anno.DnsCacheTag != "" {
		h1 ^= maphash.String(seed, anno.DnsCacheTag)
	}
	return h1, anno.DnsCacheTag != ""
}

func (c *DnsController) GetHashKey(qname string, qtype uint16, outbound *outbound.DialerGroup, dialer *dialer.Dialer) HashKey {
	// 1. 获取字符串的基础哈希（汇编加速）
	h1 := maphash.String(c.dnsCacheHashSeed, qname)

	// 2. 混入 qtype 和 outbound/dialer/cache-tag
	h1 ^= uint64(qtype) << 32
	if outbound != nil {
		// If the dialer has a dns_cache_tag annotation, use it as the cache domain.
		// Dialers with the same tag share DNS cache; different tags are isolated.
		// NOTE: the parameter names `outbound`/`dialer` shadow the packages here,
		// so the annotation type is only ever inferred, never spelled out.
		if dialer != nil {
			if anno := outbound.GetAnnotation(dialer); anno != nil {
				var isolated bool
				if h1, isolated = mixDnsAnnotationKey(h1, c.dnsCacheHashSeed, anno, c.ecsDefaultSpec); isolated {
					return HashKey(h1)
				}
			} else {
				h1, _ = mixDnsAnnotationKey(h1, c.dnsCacheHashSeed, nil, c.ecsDefaultSpec)
			}
		} else {
			h1, _ = mixDnsAnnotationKey(h1, c.dnsCacheHashSeed, nil, c.ecsDefaultSpec)
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

	// A message with the QR bit set is a response, not a query. Feeding one
	// through request routing would misroute its question section (a Reject
	// verdict would even evict a live cache family). Decline it untouched
	// and let the caller fall through to regular UDP routing toward the
	// original destination; real resolvers drop unsolicited responses
	// anyway. Past this gate every message is a query with QR already 0.
	if dnsResponse(data) {
		return false
	}

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
				// Recompute queryInfo from the switched packet: the cache
				// key and singleflight key are derived from queryInfo, so
				// reusing the original qtype here would file the A response
				// under the AAAA key (and vice versa), poisoning the cache
				// and collapsing both lookups into one singleflight entry
				// that can hand the client the wrong-question response.
				queryInfo2 := dnsQueryInfo(data2)
				if queryInfo2.qname == "" {
					// Malformed after the switch; treat as no answer.
					resultCh <- &alternateResult{err: common.Errf("alternate query malformed")}
					return
				}
				err := c.handleDNSRequest(data2, req, queryInfo2, dnsResp2)
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

	// Resolve the upstream and dial. A race group resolves to its synthetic
	// group upstream (members attached); handleDNSRequestByUpstream expands it.
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

// rejectAAAAQuery reports whether an AAAA query should be answered with a
// zero-answer response because the dialer that would forward it cannot proxy
// IPv6. Static upstreams are exempt: their answers are generated in-process
// and never traverse a dialer, so the dummy dial argument they carry (direct,
// picked only to keep the plumbing typed) must not gate them. Without the
// exemption, a direct dialer whose discovery ran before the network's IPv6 came
// up — and whose tcp4 primary never triggers a re-discovery — froze noIpv6 at
// true and silently refused every static AAAA answer while all upstream names
// kept resolving.
func rejectAAAAQuery(upstream *dns.Upstream, dialer *dialer.Dialer, qtype uint16) bool {
	if qtype != uint16(dnsmessage.TypeAAAA) || dialer == nil {
		return false
	}
	if upstream.Scheme == dns.UpstreamScheme_Static {
		return false
	}
	return dialer.NoIpv6()
}

// handleDNSRequestByUpstream resolves one client query. It loops over lookup
// rounds; each round runs a request phase (expand the upstream - a race group
// fans out to its members - pick a dialer per member, probe the cache, forward)
// and a response phase (response rules may accept, reject, or name the upstream
// of the next round). The loop counter IS the lookup depth, so there is no
// recursion and the bound also covers race-group expansion.
func (c *DnsController) handleDNSRequestByUpstream(
	data []byte,
	req *dnsRequest,
	queryInfo queryInfo,
	upstream *dns.Upstream,
	dnsResp *dnsResponseData,
) error {
	// Mirrors the candidate that answered the current round, so logging and
	// metrics keep their routing labels after the candidate's own dial argument
	// has gone back to the pool.
	dialArgument := dialArgumentPool.Get().(*dialArgument)
	defer dialArgumentPool.Put(dialArgument)

	var err error
Dial:
	for invokingDepth := 1; invokingDepth <= MaxDnsLookupDepth; invokingDepth++ {
		// ---- request phase ----
		winner, err := c.forwardDNSRequest(data, req, queryInfo, upstream, dnsResp, dialArgument)
		if err != nil {
			return err
		}
		if winner == nil {
			// Answered without forwarding (an AAAA reject). As before, that
			// bypasses response routing and the lookup-cache update.
			return nil
		}
		upstream = winner
		// ---- response phase ----
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
		ResponseIndex, nextUpstream, err = c.routing.ResponseSelect(queryInfo.qname, queryInfo.qtype, ips, uint16(dnsRcode(dnsResp.respData)), upstream, req.routingResult.Mac, req.Src.Addr())
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

// cachedAnswer is one cache probe outcome for an (upstream, dialer) pair. It is
// a value type on purpose: the common single-upstream path must not allocate.
type cachedAnswer struct {
	key      HashKey
	respData []byte
	isNew    bool
	expired  bool
	found    bool
}

// probeCachedAnswer looks the pair up in the DNS cache.
func (c *DnsController) probeCachedAnswer(queryInfo queryInfo, dialArg *dialArgument) cachedAnswer {
	if !c.enableCache {
		return cachedAnswer{}
	}
	a := cachedAnswer{
		key: c.GetHashKey(queryInfo.qname, queryInfo.qtype, dialArg.Outbound, dialArg.Dialer),
	}
	var isNew bool
	a.respData, a.expired, isNew = c.dnsCache.Get(a.key)
	if a.respData == nil {
		return cachedAnswer{}
	}
	a.found, a.isNew = true, isNew
	return a
}

// rejectAAAA answers an AAAA query with an empty response when the dialer that
// would carry it cannot proxy IPv6. It uses a fresh buffer because the query
// bytes may be shared across racing dialers.
func (c *DnsController) rejectAAAA(queryInfo queryInfo, data []byte, dnsResp *dnsResponseData) {
	if log.IsLevelEnabled(log.DebugLevel) {
		log.WithFields(log.Fields{
			"qname": queryInfo.qname,
		}).Debugln("Reject AAAA query: no dialer can proxy IPv6")
	}
	respData := pool.GetBuffer(len(data))
	copy(respData, data)
	c.reject(respData)
	dnsResp.respData = respData
	dnsResp.fromPool = true
	dnsResp.isNew = false
}

// forwardDNSRequest is the request phase of one lookup round: it resolves
// upstream (a race group fans out to its members, anything else is sent
// directly), probes the cache in config order and, on a miss, forwards - racing
// the members when there is more than one. It reuses out for the answering
// candidate's dial argument and returns the upstream that answered, or nil when
// the round was answered without forwarding.
func (c *DnsController) forwardDNSRequest(
	data []byte,
	req *dnsRequest,
	queryInfo queryInfo,
	upstream *dns.Upstream,
	dnsResp *dnsResponseData,
	out *dialArgument,
) (*dns.Upstream, error) {
	if !upstream.IsRaceGroup() {
		return c.forwardDNSSingle(data, req, queryInfo, upstream, dnsResp, out)
	}
	if upstream.RaceGroup == nil || len(upstream.RaceGroup.Members) == 0 {
		return nil, common.Errf("race group %s has no usable member", upstream.String())
	}
	return c.forwardDNSRaceGroup(data, req, queryInfo, upstream.RaceGroup.Members, dnsResp, out)
}

// forwardDNSSingle is the request phase for the common case: exactly one
// upstream and no group. It works straight on the round's pooled dial argument,
// so a cache hit allocates nothing here at all.
func (c *DnsController) forwardDNSSingle(
	data []byte,
	req *dnsRequest,
	queryInfo queryInfo,
	upstream *dns.Upstream,
	dnsResp *dnsResponseData,
	dialArg *dialArgument,
) (*dns.Upstream, error) {
	if err := c.bestDialerChooser(req, upstream, dialArg); err != nil {
		return nil, err
	}
	if rejectAAAAQuery(upstream, dialArg.Dialer, queryInfo.qtype) {
		c.rejectAAAA(queryInfo, data, dnsResp)
		return nil, nil
	}
	if a := c.probeCachedAnswer(queryInfo, dialArg); a.found {
		if a.expired && !c.dnsCache.RefreshDelayed(a.key, time.Now()) {
			// Refresh asynchronously. A failed refresh backs the next one off
			// exponentially: while an upstream is down, every query on the
			// expired entry would otherwise spawn one doomed dial apiece.
			c.refreshDNSInBackground(data, queryInfo, upstream, dialArg, a.key)
		}
		c.useCachedResponse(queryInfo, data, dnsResp, upstream, a.respData, a.isNew)
		return upstream, nil
	}
	if err := c.dialSend(data, upstream, dialArg, queryInfo, dnsResp); err != nil {
		if err = c.forwardError(err, dialArg, queryInfo, dnsResp); err != nil {
			return nil, err
		}
	}
	return upstream, nil
}

// dnsForwardCandidate is one member of a race group in a single lookup round.
type dnsForwardCandidate struct {
	upstream *dns.Upstream
	// dialArg is a value, not a pooled pointer: the candidate already lives on
	// the heap, and owning the argument outright removes every get/put pairing
	// question (and the chance of copying it after it went back to the pool).
	dialArg dialArgument
	// noIpv6 marks a candidate whose dialer cannot proxy IPv6. AAAA queries
	// skip such candidates unless every candidate is one.
	noIpv6 bool
	answer cachedAnswer
}

// dnsForwardResult is what a member of a concurrent round reports back.
type dnsForwardResult struct {
	candidate *dnsForwardCandidate
	win       bool
	err       error
}

// forwardDNSRaceGroup is the request phase for a race group: every member is a
// candidate, the cache is probed in config order, and a miss forwards on all
// of them concurrently.
func (c *DnsController) forwardDNSRaceGroup(
	data []byte,
	req *dnsRequest,
	queryInfo queryInfo,
	members []*dns.Upstream,
	dnsResp *dnsResponseData,
	out *dialArgument,
) (*dns.Upstream, error) {
	// Choose a dialer per member up front: it decides both the cache key and
	// the forwarding route, and keeping the choice out of the spawned
	// goroutines means they never touch the caller's *dnsRequest, which Handle
	// recycles as soon as the query is answered.
	// A value slice, not a slice of pointers: the candidates are inline in one
	// backing array, so a fan-out costs one allocation rather than one per
	// member. The array cannot stay on the stack because the element addresses
	// escape into bestDialerChooser, a func-typed field whose callee is unknown.
	// The capacity is exact, so the element pointers stay valid while building.
	candidates := make([]dnsForwardCandidate, len(members))
	n := 0
	var chooserErr error
	for _, member := range members {
		cand := &candidates[n]
		cand.upstream = member
		if err := c.bestDialerChooser(req, member, &cand.dialArg); err != nil {
			chooserErr = err
			continue
		}
		cand.noIpv6 = rejectAAAAQuery(member, cand.dialArg.Dialer, queryInfo.qtype)
		n++
	}
	candidates = candidates[:n]
	if len(candidates) == 0 {
		if chooserErr != nil {
			return nil, chooserErr
		}
		return nil, common.Errf("no usable upstream for %q", queryInfo.qname)
	}

	// AAAA queries are rejected only when NO member can proxy IPv6: a group may
	// well contain one that can (race(cf4_dns, cf6_dns)), and rejecting on the
	// first member that cannot would answer an empty AAAA even though another
	// member could have resolved it.
	canProxyIpv6 := false
	for i := range candidates {
		if !candidates[i].noIpv6 {
			canProxyIpv6 = true
			break
		}
	}
	if !canProxyIpv6 {
		c.rejectAAAA(queryInfo, data, dnsResp)
		return nil, nil
	}
	usable := candidates[:0]
	for i := range candidates {
		if candidates[i].noIpv6 {
			continue
		}
		usable = append(usable, candidates[i])
	}

	// Cache probe in config order: the first member with a fresh entry answers;
	// otherwise the first expired entry is served stale while every member's own
	// entry is refreshed in the background (their flight keys include the
	// upstream, so that refresh races the whole group).
	var fresh, stale *dnsForwardCandidate
	for i := range usable {
		cand := &usable[i]
		if cand.answer = c.probeCachedAnswer(queryInfo, &cand.dialArg); !cand.answer.found {
			continue
		}
		if !cand.answer.expired {
			fresh = cand
			break
		}
		if stale == nil {
			stale = cand
		}
	}
	if fresh != nil {
		*out = fresh.dialArg
		c.useCachedResponse(queryInfo, data, dnsResp, fresh.upstream, fresh.answer.respData, fresh.answer.isNew)
		return fresh.upstream, nil
	}
	if stale != nil {
		*out = stale.dialArg
		for i := range usable {
			cand := &usable[i]
			if cand.answer.found && cand.answer.expired && !c.dnsCache.RefreshDelayed(cand.answer.key, time.Now()) {
				c.refreshDNSInBackground(data, queryInfo, cand.upstream, &cand.dialArg, cand.answer.key)
			}
		}
		c.useCachedResponse(queryInfo, data, dnsResp, stale.upstream, stale.answer.respData, stale.answer.isNew)
		return stale.upstream, nil
	}

	// Miss: forward. A single candidate sends directly; a race group's members
	// send concurrently and the first success wins.
	if len(usable) == 1 {
		cand := &usable[0]
		if err := c.dialSend(data, cand.upstream, &cand.dialArg, queryInfo, dnsResp); err != nil {
			if err = c.forwardError(err, &cand.dialArg, queryInfo, dnsResp); err != nil {
				return nil, err
			}
		}
		*out = cand.dialArg
		return cand.upstream, nil
	}

	var winnerFlag atomic.Bool
	results := make(chan dnsForwardResult, len(usable))
	for i := range usable {
		cand := &usable[i]
		// Snapshot the query BEFORE spawning: this function returns as soon as a
		// winner is known, but losing goroutines keep running, and Handle
		// recycles the request buffer the moment it returns. Taking the copy in
		// the synchronously executed loop body happens-before that reuse; the
		// copy inside the goroutine would not be safe.
		dataCopy := pool.GetBuffer(len(data))
		copy(dataCopy, data)
		go func(cand *dnsForwardCandidate, dataCopy []byte) {
			defer pool.PutBuffer(dataCopy)
			localResp := dnsResponseDataPool.Get().(*dnsResponseData)
			err := c.dialSend(dataCopy, cand.upstream, &cand.dialArg, queryInfo, localResp)
			if err != nil {
				err = c.forwardError(err, &cand.dialArg, queryInfo, localResp)
			}
			win := err == nil && winnerFlag.CompareAndSwap(false, true)
			if win {
				*out = cand.dialArg
				*dnsResp = *localResp
			} else if localResp.respData != nil && localResp.fromPool {
				pool.PutBuffer(localResp.respData)
			}
			*localResp = dnsResponseData{}
			dnsResponseDataPool.Put(localResp)
			results <- dnsForwardResult{candidate: cand, win: win, err: err}
		}(cand, dataCopy)
	}
	var firstErr error
	for range len(usable) {
		res := <-results
		if res.win {
			return res.candidate.upstream, nil
		}
		if firstErr == nil && res.err != nil {
			firstErr = res.err
		}
	}
	if firstErr == nil {
		firstErr = common.Errf("no race member produced an answer")
	}
	return nil, fmt.Errorf("all %d race upstreams failed: %w", len(usable), firstErr)
}

// useCachedResponse files a cached answer into dnsResp, stamped with the
// client's transaction id (the cache stores answers under their own id).
func (c *DnsController) useCachedResponse(
	queryInfo queryInfo,
	data []byte,
	dnsResp *dnsResponseData,
	upstream *dns.Upstream,
	respData []byte,
	isNew bool,
) {
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
}

// refreshDNSInBackground refreshes an expired cache entry without blocking the
// query. The rewrite (payload clamp, ECS policy) happens here, as it would on
// the forwarding path: the refresh must query with the same rewritten message
// the entry was built from. The pooled dial argument stays with the caller.
func (c *DnsController) refreshDNSInBackground(data []byte, queryInfo queryInfo, upstream *dns.Upstream, dialArg *dialArgument, key HashKey) {
	rewritten, release := rewriteUpstreamQuery(data, c.resolveEcsPolicy(dialArg.Outbound, dialArg.Dialer))
	p := obtainDnsRefreshParam(rewritten, queryInfo, upstream, dialArg)
	if release != nil {
		release()
	}
	go func(c *DnsController, p *dnsRefreshParam, hashKey HashKey) {
		defer recycleDnsRefreshParam(p)
		_, leader, _, err := c.singleFlightForwardDNS(p.qi, p.data, p.upstream, &p.dialArg, true)
		if err != nil {
			// Only the singleflight leader postpones: shared callers observed
			// the same failure and would double-count the attempt.
			if leader {
				c.dnsCache.PostponeRefresh(hashKey, time.Now())
			}
			log.Warnf("failed to refresh dns cache for %v: %+v", p.qi, err)
		}
	}(c, p, key)
}

// forwardError applies the forwarding-failure policy: wrap the error with its
// routing context, count it, and mark the dialer unavailable when the failure
// says something about the route. It returns nil when the error came with a
// usable response, in which case the caller carries on with that response.
func (c *DnsController) forwardError(err error, dialArg *dialArgument, queryInfo queryInfo, dnsResp *dnsResponseData) error {
	isNetError, isClosed, isTimeout, isTemporary := GetNetErrorInfo(err)
	if !isNetError || isClosed || !dnsResponse(dnsResp.respData) || (!isTimeout && dialArg.Dialer.NeedAliveState()) {
		err = common.
			In("DialContext").
			With("Is NetError", isNetError).
			With("Is Temporary", isTemporary).
			With("Is Timeout", isTimeout).
			With("qname", queryInfo.qname).
			With("qtype", queryInfo.qtype).
			With("Outbound", dialArg.Outbound.Name).
			With("Dialer", dialArg.Dialer.Name).
			Wrapf(err, "DNS dialSend error")
		labels := [...]string{
			dialArg.Outbound.Name,
			dialArg.Dialer.Property.SubscriptionTag,
			dialArg.Dialer.Name,
			dialArg.networkType.String(),
		}
		common.Metrics.ErrorCount.With4(labels).Inc()

		if !isNetError || isClosed || !dnsResponse(dnsResp.respData) {
			return err
		}
		// !isTimeout && dialArgument.Dialer.NeedAliveState()
		dialArg.Dialer.ReportUnavailable()
		return err
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

// rewriteUpstreamQuery applies the raw-byte rewrites dae performs on a client
// query before forwarding it upstream: the EDNS0 UDP payload size clamp and
// the effective ECS policy. The input query may be shared across racing
// dialers, so a rewrite always produces a fresh buffer and the caller's bytes
// are never mutated. release is nil when nothing was taken from the pool;
// otherwise it returns those buffers and must be called once the query is no
// longer needed.
func rewriteUpstreamQuery(data []byte, ecsSpec *dialer.EcsSpec) (out []byte, release func()) {
	out = data
	var pooled [][]byte
	if clamped, changed := dnsClampUDPSize(out, dnsUDPPayloadCap); changed {
		out = clamped
		pooled = append(pooled, clamped)
	}
	if ecsSpec != nil {
		if rewritten, changed := dnsRewriteEcs(out, ecsSpec); changed {
			out = rewritten
			pooled = append(pooled, rewritten)
		}
	}
	if len(pooled) == 0 {
		return out, nil
	}
	return out, func() {
		for _, b := range pooled {
			pool.PutBuffer(b)
		}
	}
}

// dialSend forwards one query to one upstream and files the answer in dnsResp.
// The cache is NOT consulted here - the request phase probes it, serves stale
// entries and launches refreshes - so this is only the upstream exchange itself
// (deduplicated per upstream+dialer by the singleflight, which also saves the
// answer to the cache).
func (c *DnsController) dialSend(data []byte, upstream *dns.Upstream, dialArg *dialArgument, queryInfo queryInfo, dnsResp *dnsResponseData) error {
	// Cap the client's advertised EDNS0 UDP payload size (see
	// dnsUDPPayloadCap) and apply the effective EDNS0 Client Subnet policy
	// (global dns.ecs default, overridden by the dialer's [ecs: ...]
	// annotation) before forwarding. The input query may be shared across
	// racing dialers, so a rewrite always produces a fresh buffer; the
	// caller's bytes are never mutated.
	data, releaseQuery := rewriteUpstreamQuery(data, c.resolveEcsPolicy(dialArg.Outbound, dialArg.Dialer))
	if releaseQuery != nil {
		defer releaseQuery()
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

// singleFlightKey returns the singleflight dedup key for one upstream
// exchange. Unlike the response cache key it includes the upstream identity:
// race() members that resolve to the same outbound group must fly separately,
// otherwise the singleflight would collapse them into one upstream query - the
// first registrant's upstream - and a down upstream would fail the whole race
// instead of failing over to the next member. The upstream pointer is folded
// in the same way GetHashKey folds the outbound pointer: it is stable for the
// lifetime of a controller generation, and the dedup it buys (concurrent
// identical lookups for the same upstream still merge) is worth the pointer
// identity. Note this makes ad-hoc asis upstreams (built per query) never
// merge - arguably more correct, since merging answers across different
// destinations was questionable to begin with.
func (c *DnsController) singleFlightKey(qi queryInfo, upstream *dns.Upstream, dialArgument *dialArgument) HashKey {
	key := c.GetHashKey(qi.qname, qi.qtype, dialArgument.Outbound, dialArgument.Dialer)
	return key ^ HashKey(uintptr(unsafe.Pointer(upstream)))
}

func (c *DnsController) singleFlightForwardDNS(
	qi queryInfo, data []byte, upstream *dns.Upstream, dialArgument *dialArgument, isBackground bool) (r []byte, leader bool, shared bool, err error) {
	hashKey := c.singleFlightKey(qi, upstream, dialArgument)
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
			if c.dnsForwardersClosed.Load() {
				return nil, ErrDnsForwardersClosed
			}
			// Try to store the new forwarder, but use LoadOrStore to handle concurrent creation
			actualValue, _ := c.dnsForwarderCache.LoadOrStore(forwarderKey, forwarder)
			forwarder = actualValue.(DnsForwarder)
			if c.dnsForwardersClosed.Load() {
				// The controller was closed between the entry check and
				// this store. Stores that landed before the sweep's Range
				// reached the key were closed by it; a store landing after
				// would leak a forwarder nobody owns, so close it here and
				// fail the in-flight query.
				if closer, ok := forwarder.(io.Closer); ok {
					_ = closer.Close()
				}
				return nil, ErrDnsForwardersClosed
			}
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
	for i := range subLen {
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
	c.dnsForwardersClosed.Store(true)
	c.dnsForwarderCache.Range(func(key, value any) bool {
		if forwarder, ok := value.(io.Closer); ok {
			forwarder.Close()
		}
		return true
	})
	return nil
}
