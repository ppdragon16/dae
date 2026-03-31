/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"fmt"
	"io"
	"math"
	"net/netip"
	"strings"
	"sync"
	"time"

	"github.com/daeuniverse/dae/common"
	"github.com/daeuniverse/dae/common/netutils"
	"golang.org/x/sync/singleflight"

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
	dnsCache           *commonDnsCache[dnsCacheKey]
	dnsForwarderCache  sync.Map // map[dnsForwarderKey]DnsForwarder
	requestSelectCache *common.TimeWheelCache[queryInfo, consts.DnsRequestOutboundIndex]
	// mu protects deadlineTimers
	mu              sync.Mutex
	deadlineTimers  map[string]map[netip.Addr]*time.Timer
	sniffVerifyMode consts.SniffVerifyMode

	singleFlightGroup singleflight.Group
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

	return &DnsController{
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
		dnsCache:           newCommonDnsCache[dnsCacheKey](),
		requestSelectCache: common.NewTimeWheelCache[queryInfo, consts.DnsRequestOutboundIndex](1*time.Hour, 5*time.Second, nil),
		deadlineTimers:     make(map[string]map[netip.Addr]*time.Timer),
	}, nil
}

func (c *DnsController) UpdateDnsCacheTtl(cacheKey dnsCacheKey, answers []dnsmessage.RR) {
	fixedTtl, _ := c.fixedDomainTtl[cacheKey.qname]
	c.dnsCache.UpdateAnswers(cacheKey, answers, fixedTtl)
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

type dnsForwarderKey struct {
	upstream     dns.Upstream
	dialArgument dialArgument
}

type queryInfo struct {
	qname string
	qtype uint16
}

type dnsCacheKey struct {
	queryInfo
	outbound *outbound.DialerGroup
}

func (k dnsCacheKey) String() string {
	return k.qname + string(k.qtype) + k.outbound.Name
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

			// TODO: ignoreFixedTTL?
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
		netErr, ok := IsNetError(err)
		if !ok || !netErr.Temporary() {
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

// TODO: 除了dialSend, 不应该有可预期的 err
// TODO: qname=. qtype=2 的查询是什么, 为什么没有缓存, 因为AsIs?
// TODO: 如果AsIs都不缓存的话，如果一个server可用一个不可用，那就是远端sever的问题?
func (c *DnsController) handleDNSRequest(
	dnsMessage *dnsmessage.Msg,
	req *dnsRequest,
	queryInfo queryInfo,
) error {
	var err error
	// Route Requset
	RequestIndex, queryInfo, ok := c.requestSelectCache.GetWithKey(queryInfo)
	if !ok {
		RequestIndex, err = c.routing.RequestSelect(queryInfo.qname, queryInfo.qtype)
		if err != nil {
			return err
		}
		c.requestSelectCache.Save(queryInfo, RequestIndex)
	}

	if RequestIndex == consts.DnsRequestOutboundIndex_Reject {
		c.reject(dnsMessage)
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
	var isNew bool
	var reqMsg *dnsmessage.Msg
	if !c.routing.HasResponseRules() {
		reqMsg = dnsMessage
	} else {
		reqMsg = dnsMessage.Copy()
	}
	dialArgument := dialArgumentPool.Get().(*dialArgument)
	defer dialArgumentPool.Put(dialArgument)
Dial:
	for invokingDepth := 1; invokingDepth <= MaxDnsLookupDepth; invokingDepth++ {
		if log.IsLevelEnabled(log.DebugLevel) {
			log.WithFields(log.Fields{
				"question": dnsMessage.Question,
				"upstream": upstream.String(),
			}).Debugln("Request to DNS upstream")
		}

		// Select best dial arguments (outbound, dialer, l4proto, ipversion, etc.)
		if err := c.bestDialerChooser(req, upstream, dialArgument); err != nil {
			return err
		}

		// TODO: 这里可能不可以这样做
		isNew, err = c.dialSend(dnsMessage, upstream, dialArgument, queryInfo)
		if err != nil {
			netErr, ok := IsNetError(err)
			if !ok || !dnsMessage.Response || (!netErr.Timeout() && dialArgument.Dialer.NeedAliveState()) {
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
				if !ok || !dnsMessage.Response {
					return err
				} else if !netErr.Timeout() && dialArgument.Dialer.NeedAliveState() {
					labels := common.GetPrometheusLabels(
						dialArgument.Outbound.Name,
						dialArgument.Dialer.Property.SubscriptionTag,
						dialArgument.Dialer.Name,
						dialArgument.networkType.String())
					common.ErrorCount.With(labels).Inc()
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
				// Reject
				// TODO: cache response reject.
				c.reject(dnsMessage)
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
				"question":      dnsMessage.Question,
				"last_upstream": upstream.String(),
				"next_upstream": nextUpstream.String(),
			}).Debugln("Change DNS upstream and resend")
		}
		upstream = nextUpstream
		reqMsg.CopyTo(dnsMessage)
	}
	// TODO: dial_mode: domain 的逻辑失效问题
	// TODO: 我们现在缓存了它, 但并不响应缓存, 这是一个workround, 会导致污染其他非AsIs的查询
	// TODO: AsIs也需要更新domain_routing_map? 不然没有办法sniff, 并且考虑到有些应用会使用不同的DNS, 必须对全部 upstream 更新
	// TODO: RemoveCache
	// TODO: 不再存储Bitmap, 提高更新代码可读性
	// 但在有bump_map的情况下这不是大问题
	// TOOD: 细分日志
	switch {
	case !dnsMessage.Response,
		len(dnsMessage.Answer) == 0,
		len(dnsMessage.Question) == 0,               // Check healthy resp.
		dnsMessage.Rcode != dnsmessage.RcodeSuccess: // Check suc resp.
		return nil
	}

	if isNew {
		domainBitmap := common.ObtainDomainBitmap()
		defer common.RecycleDomainBitmap(domainBitmap)
		if allZero, shouldUpdate := c.checkDomainBitmap(queryInfo.qname, domainBitmap); shouldUpdate {
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
			return c.updateLookupCache(queryInfo.qname, domainBitmap, allZero, ips, time.Duration(ttl)*time.Second)
		}
	}
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
		if accepted {
			tcpDnsStr := ""
			if req.isTcp {
				tcpDnsStr = "(TCP)"
			}
			log.WithFields(fields).Infof("[DNS%s] %v <-> %v", tcpDnsStr, RefineSourceToShow(req.Src, req.Dst.Addr()), RefineAddrPortToShow(dialArgument.Target))
		} else {
			log.WithFields(fields).Infof("[DNS] %v <-> %v Reject with empty answer", RefineSourceToShow(req.Src, req.Dst.Addr()), RefineAddrPortToShow(dialArgument.Target))
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
	c.mu.Lock()
	defer c.mu.Unlock()

	bitmap := (*[32]uint32)(domainBitmap)
	for _, ip := range ips {
		if _, ok := c.deadlineTimers[qname]; !ok {
			c.deadlineTimers[qname] = make(map[netip.Addr]*time.Timer)
		}
		if timer, ok := c.deadlineTimers[qname][ip]; ok {
			timer.Reset(lookupTTL)
			continue
		}
		if !allZero {
			if err := c.newLookupCache(ip, bitmap); err != nil {
				return err
			}
			common.CoreIpDomainBitmap.Inc()
		}
		c.deadlineTimers[qname][ip] = time.AfterFunc(lookupTTL, func() {
			c.mu.Lock()
			defer c.mu.Unlock()
			if !allZero {
				if err := c.lookupCacheTimeout(ip, bitmap); err == nil {
					common.CoreIpDomainBitmap.Dec()
				}
			}
			if timer, ok := c.deadlineTimers[qname][ip]; ok {
				timer.Stop()
				delete(c.deadlineTimers[qname], ip)
			}
			if len(c.deadlineTimers[qname]) == 0 {
				delete(c.deadlineTimers, qname)
			}
			common.DeadlineTimers.Dec()
		})
		common.DeadlineTimers.Inc()
	}
	return nil
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
	cacheKey dnsCacheKey
	upstream *dns.Upstream
	dialArg  dialArgument
}

var dnsRefreshParamPool = sync.Pool{
	New: func() any { return &dnsRefreshParam{} },
}

func obtainDnsRefreshParam(data *dnsmessage.Msg, cacheKey *dnsCacheKey, upstream *dns.Upstream, dialArg *dialArgument) *dnsRefreshParam {
	p := dnsRefreshParamPool.Get().(*dnsRefreshParam)
	p.data = data
	p.cacheKey = *cacheKey
	p.upstream = upstream
	p.dialArg = *dialArg
	return p
}

func recycleDnsRefreshParam(p *dnsRefreshParam) {
	p.data = nil
	dnsRefreshParamPool.Put(p)
}

func (c *DnsController) dialSend(msg *dnsmessage.Msg, upstream *dns.Upstream, dialArg *dialArgument, queryInfo queryInfo) (bool, error) {
	cacheKey := dnsCacheKey{queryInfo: queryInfo, outbound: dialArg.Outbound}
	// Lookup Cache
	if c.enableCache {
		if rr, fetchedAt, isNew := c.dnsCache.Get(cacheKey); rr != nil {
			originalMsgForExpiredFetch := FillMsgByCache(msg, rr, fetchedAt)
			if originalMsgForExpiredFetch != nil {
				// Refresh cache asynchronously.
				go c.refreshDnsCache(obtainDnsRefreshParam(originalMsgForExpiredFetch, &cacheKey, upstream, dialArg))
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
	msgResp, err := c.singleFlightForwardDNS(cacheKey, msg, upstream, dialArg)
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

func (c *DnsController) refreshDnsCache(p *dnsRefreshParam) {
	defer recycleDnsRefreshParam(p)
	if _, err := c.singleFlightForwardDNS(p.cacheKey, p.data, p.upstream, &p.dialArg); err != nil {
		log.Warnf("failed to refresh dns cache for %v: %+v", p.cacheKey, err)
	}
}

func (c *DnsController) singleFlightForwardDNS(
	cacheKey dnsCacheKey, msg *dnsmessage.Msg, upstream *dns.Upstream, dialArgument *dialArgument) (*dnsmessage.Msg, error) {
	resp, err, _ := c.singleFlightGroup.Do(cacheKey.String(), func() (any, error) {
		var forwarder DnsForwarder
		key := dnsForwarderKey{upstream: *upstream, dialArgument: *dialArgument}
		// get forwarder from cache
		value, ok := c.dnsForwarderCache.Load(key)
		if ok {
			forwarder = value.(DnsForwarder)
		} else {
			var err error
			if upstream.Scheme == dns.UpstreamScheme_Static {
				forwarder = &StaticForwarder{
					getEntryFn: func() (*config.DnsStaticEntry, bool) {
						return c.routing.GetStaticEntry(upstream.Hostname)
					}}
			} else {
				forwarder, err = newDnsForwarder(upstream, *dialArgument)
			}
			if err != nil {
				return nil, err
			}
			// Try to store the new forwarder, but use LoadOrStore to handle concurrent creation
			actualValue, _ := c.dnsForwarderCache.LoadOrStore(key, forwarder)
			forwarder = actualValue.(DnsForwarder)
		}

		err := forwarder.ForwardDNS(msg)
		if err != nil {
			return nil, err
		}

		if log.IsLevelEnabled(log.DebugLevel) {
			log.WithFields(log.Fields{
				"qname": cacheKey.qname,
				"qtype": cacheKey.qtype,
				"rcode": msg.Rcode,
				"ans":   FormatDnsRsc(msg.Answer),
			}).Debugf("Got DNS response")
		}

		// TODO: 细分日志
		if !msg.Response {
			return nil, common.Errf("DNS message response flag is unset")
		}
		switch {
		case len(msg.Question) == 0, // Check healthy resp.
			msg.Rcode != dnsmessage.RcodeSuccess: // Check suc resp.
			if log.IsLevelEnabled(log.DebugLevel) {
				log.WithFields(log.Fields{
					"qname": cacheKey.qname,
					"qtype": cacheKey.qtype,
					"rcode": msg.Rcode,
					"ans":   FormatDnsRsc(msg.Answer),
				}).Debugf("Not a valid DNS response")
			}
			return msg, nil
		}

		// Skip cache for static entries to allow dynamic updates
		if c.enableCache && upstream.Scheme != dns.UpstreamScheme_Static {
			if log.IsLevelEnabled(log.DebugLevel) {
				log.WithFields(log.Fields{
					"qname":    cacheKey.qname,
					"qtype":    cacheKey.qtype,
					"rcode":    msg.Rcode,
					"ans":      FormatDnsRsc(msg.Answer),
					"upstream": upstream,
					"dialer":   dialArgument.Dialer,
					"outbound": dialArgument.Outbound,
				}).Debugf("Update DNS record cache")
			}
			c.UpdateDnsCacheTtl(cacheKey, msg.Answer)
		}
		return msg, nil
	})
	if resp != nil {
		return resp.(*dnsmessage.Msg), err
	}
	return nil, err
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

	// Clean up all deadline timers to prevent goroutine leaks
	for _, ipTimers := range c.deadlineTimers {
		for _, timer := range ipTimers {
			if timer != nil {
				timer.Stop()
			}
		}
	}
	c.deadlineTimers = make(map[string]map[netip.Addr]*time.Timer)

	// Close all DNS forwarders
	c.dnsForwarderCache.Range(func(key, value any) bool {
		if forwarder, ok := value.(io.Closer); ok {
			forwarder.Close()
		}
		return true
	})
	return nil
}
