/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"encoding/binary"
	"fmt"
	"io"
	"math"
	"net/netip"
	"sync"
	"time"

	"github.com/daeuniverse/dae/common"
	"github.com/daeuniverse/dae/common/netutils"
	"github.com/prometheus/client_golang/prometheus"
	"golang.org/x/sync/singleflight"

	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/component/dns"
	"github.com/daeuniverse/dae/component/outbound"
	"github.com/daeuniverse/dae/component/outbound/dialer"
	"github.com/daeuniverse/outbound/pkg/fastrand"
	"github.com/daeuniverse/outbound/pool"
	dnsmessage "github.com/miekg/dns"
	"github.com/samber/oops"
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
	MatchBitmap        func(fqdn string) []uint32
	NewLookupCache     func(ip netip.Addr, domainBitmap [32]uint32) error
	LookupCacheTimeout func(ip netip.Addr, domainBitmap [32]uint32) error
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

	matchBitmap        func(fqdn string) []uint32
	newLookupCache     func(ip netip.Addr, domainBitmap [32]uint32) error
	lookupCacheTimeout func(ip netip.Addr, domainBitmap [32]uint32) error
	bestDialerChooser  func(req *dnsRequest, upstream *dns.Upstream, outArg *dialArgument) error

	fixedDomainTtl    map[string]int
	minSniffingTtl    time.Duration
	enableCache       bool
	dnsCache          *commonDnsCache[dnsCacheKey]
	dnsForwarderCache sync.Map // map[dnsForwarderKey]DnsForwarder
	// mu protects deadlineTimers
	mu              sync.Mutex
	deadlineTimers  map[string]map[netip.Addr]*time.Timer
	sniffVerifyMode consts.SniffVerifyMode

	singleFlightGroup singleflight.Group
	dialArgumentPool  sync.Pool
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

		fixedDomainTtl:    option.FixedDomainTtl,
		minSniffingTtl:    option.MinSniffingTtl,
		enableCache:       option.EnableCache,
		sniffVerifyMode:   option.SniffVerifyMode,
		dnsForwarderCache: sync.Map{},
		dnsCache:          newCommonDnsCache[dnsCacheKey](),
		deadlineTimers:    make(map[string]map[netip.Addr]*time.Timer),

		dialArgumentPool: sync.Pool{New: func() any { return &dialArgument{} }},
	}, nil
}

func (c *DnsController) UpdateDnsCacheTtl(cacheKey dnsCacheKey, data []byte) {
	infos, _ := dnsExtractMetadata(data)
	fixedTtl, _ := c.fixedDomainTtl[cacheKey.qname]
	c.dnsCache.UpdateAnswers(cacheKey, data, infos, fixedTtl)
}

type dnsRequest struct {
	src           netip.AddrPort
	dst           netip.AddrPort
	routingResult *bpfRoutingResult
	isTcp         bool
}

type dialArgument struct {
	networkType *common.NetworkType
	Dialer      *dialer.Dialer
	Outbound    *outbound.DialerGroup
	Target      netip.AddrPort
	// mark        uint32
}

type dnsForwarderKey struct {
	upstream     string
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
}

type dnsCacheKey struct {
	queryInfo
	outbound *outbound.DialerGroup
}

func (k dnsCacheKey) String() string {
	return fmt.Sprintf("%v,%v,%v", k.qname, k.qtype, k.outbound.Name)
}

func dnsQueryInfo(data []byte) (queryInfo queryInfo) {
	if qname, off, err := dnsDomain(data, 12); err == nil {
		if len(data) >= off+4 {
			qtype := binary.BigEndian.Uint16(data[off : off+2])
			qclass := binary.BigEndian.Uint16(data[off+2 : off+4])
			if qclass == uint16(dnsmessage.ClassINET) {
				queryInfo.qname = dnsmessage.CanonicalName(qname)
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

	if dnsResponse(data) {
		log.Errorln("DNS request expected but DNS response received")
	}

	queryInfo := dnsQueryInfo(data)
	if log.IsLevelEnabled(log.TraceLevel) {
		log.Tracef("Received UDP(DNS) %v <-> %v: %v %v",
			RefineSourceToShow(req.src, req.dst.Addr()), req.dst.String(), queryInfo.qname, queryInfo.qtype)
	}

	id := dnsId(data)
	// Avoids duplicated id from clients, so make the id unique.
	dnsIdSet(data, uint16(fastrand.Intn(math.MaxUint16)))

	var err error
	var dnsResp dnsResponseData
	// Check ip version preference and qtype.
	switch queryInfo.qtype {
	case dnsmessage.TypeA, dnsmessage.TypeAAAA:
		if c.qtypePrefer == 0 {
			dnsResp, err = c.handleDNSRequest(data, req, queryInfo)
		} else {
			// Try to make both A and AAAA lookups.
			// TODO: ignoreFixedTTL?
			resultCh := make(chan struct {
				dnsResp dnsResponseData
				err     error
			}, 1)
			go func() {
				data2 := pool.GetBuffer(len(data))
				defer pool.PutBuffer(data2)
				copy(data2, data)
				dnsSwitchQtype(data2)

				dnsResp2 := dnsResponseData{}
				var err error
				if dnsResp2, err = c.handleDNSRequest(data2, req, queryInfo); err == nil {
					ips, _ := dnsAnswers(dnsResp2.respData)
					if len(ips) == 0 {
						dnsResp2 = dnsResponseData{}
					}
				}
				resultCh <- struct {
					dnsResp dnsResponseData
					err     error
				}{dnsResp2, err}
			}()
			dnsResp, err = c.handleDNSRequest(data, req, queryInfo)
			result := <-resultCh
			if result.dnsResp.respData != nil && result.dnsResp.fromPool {
				defer pool.PutBuffer(result.dnsResp.respData)
			}
			err = oops.Join(err, result.err)
			if err != nil {
				break
			}
			if c.qtypePrefer != queryInfo.qtype && result.dnsResp.respData != nil {
				c.reject(dnsResp.respData)
			}
		}
	default:
		dnsResp, err = c.handleDNSRequest(data, req, queryInfo)
	}
	if dnsResp.respData != nil && dnsResp.fromPool {
		defer pool.PutBuffer(dnsResp.respData)
	}
	dataToWrite := dnsResp.respData
	if err != nil {
		netErr, ok := IsNetError(err)
		err = oops.
			With("Is NetError", ok).
			With("Is Temporary", ok && netErr.Temporary()).
			With("Is Timeout", ok && netErr.Timeout()).
			Wrapf(err, "failed to make dns request")
		if !ok || !netErr.Temporary() {
			log.Warningf("%+v", err)
		}
		dataToWrite = data
		dnsRcodeSet(dataToWrite, dnsmessage.RcodeServerFailure)
	}
	// Keep the id the same with request.
	dnsIdSet(dataToWrite, id)
	if err = sendPkt(dataToWrite, req.dst, req.src); err != nil {
		log.Warningf("%+v", oops.Wrapf(err, "failed to send dns message back"))
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
) (dnsResponseData, error) {
	// Route Requset
	RequestIndex, err := c.routing.RequestSelect(queryInfo.qname, queryInfo.qtype)
	if err != nil {
		return dnsResponseData{}, err
	}

	if RequestIndex == consts.DnsRequestOutboundIndex_Reject {
		c.reject(data)
		return dnsResponseData{respData: data, fromPool: false}, nil
	}

	var upstream *dns.Upstream
	if RequestIndex == consts.DnsRequestOutboundIndex_AsIs {
		// As-is should not be valid in response routing, thus using connection realDest is reasonable.
		upstream = &dns.Upstream{
			Scheme:   "udp",
			Hostname: req.dst.Addr().String(),
			Port:     req.dst.Port(),
			Ip46:     netutils.FromAddr(req.dst.Addr()),
			IsAsIs:   true,
		}
	} else {
		// Get corresponding upstream.
		upstream, err = c.routing.GetUpstream(RequestIndex)
		if err != nil {
			return dnsResponseData{}, err
		}
	}

	// Dial and re-route
	var dnsResp dnsResponseData
	dialArgument := c.dialArgumentPool.Get().(*dialArgument)
	defer c.dialArgumentPool.Put(dialArgument)
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
			return dnsResponseData{}, err
		}

		// TODO: 这里可能不可以这样做
		dnsResp, err = c.dialSend(data, upstream, dialArgument, queryInfo)
		if err != nil {
			netErr, ok := IsNetError(err)
			err = oops.
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
				return dnsResp, err
			} else if !netErr.Timeout() {
				if dialArgument.Dialer.NeedAliveState() {
					labels := prometheus.Labels{
						"outbound": dialArgument.Outbound.Name,
						"subtag":   dialArgument.Dialer.Property.SubscriptionTag,
						"dialer":   dialArgument.Dialer.Name,
						"network":  dialArgument.networkType.String(),
					}
					common.ErrorCount.With(labels).Inc()
					dialArgument.Dialer.ReportUnavailable()
					return dnsResp, err
				}
			}
		}

		if !dnsResponse(dnsResp.respData) {
			return dnsResp, fmt.Errorf("DNS response expected but DNS request received")
		}
		if !c.routing.HasResponseRules() {
			break Dial
		}
		// Route response.
		var ResponseIndex consts.DnsResponseOutboundIndex
		var nextUpstream *dns.Upstream
		ips, _ := dnsAnswers(dnsResp.respData)
		ResponseIndex, nextUpstream, err = c.routing.ResponseSelect(queryInfo.qname, queryInfo.qtype, ips, upstream)
		if err != nil {
			return dnsResp, err
		}
		if ResponseIndex.IsReserved() {
			c.logDnsResponse(req, dialArgument, queryInfo, ResponseIndex == consts.DnsResponseOutboundIndex_Accept)
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
				return dnsResp, oops.Errorf("unknown upstream: %v", ResponseIndex.String())
			}
		}
		if invokingDepth == MaxDnsLookupDepth {
			return dnsResp, oops.Errorf("too deep DNS lookup invoking (depth: %v); there may be infinite loop in your DNS response routing", MaxDnsLookupDepth)
		}
		if log.IsLevelEnabled(log.DebugLevel) {
			log.WithFields(log.Fields{
				"qname":         queryInfo.qname,
				"last_upstream": upstream.String(),
				"next_upstream": nextUpstream.String(),
			}).Debugln("Change DNS upstream and resend")
		}
		upstream = nextUpstream
	}
	// TODO: dial_mode: domain 的逻辑失效问题
	// TODO: 我们现在缓存了它, 但并不响应缓存, 这是一个workround, 会导致污染其他非AsIs的查询
	// TODO: AsIs也需要更新domain_routing_map? 不然没有办法sniff, 并且考虑到有些应用会使用不同的DNS, 必须对全部 upstream 更新
	// TODO: RemoveCache
	// TODO: 不再存储Bitmap, 提高更新代码可读性
	// 但在有bump_map的情况下这不是大问题
	// TOOD: 细分日志
	if dnsResp.isNew && isDnsResponseValid(dnsResp.respData) {
		if domainBitmap, allZero, shouldUpdate := c.checkDomainBitmap(queryInfo.qname); shouldUpdate {
			ips, ttl := dnsAnswers(dnsResp.respData)
			err = c.updateLookupCache(queryInfo.qname, domainBitmap, allZero, ips, time.Duration(ttl)*time.Second)
		}
	}
	return dnsResp, err
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
			log.WithFields(fields).Infof("[DNS%s] %v <-> %v", tcpDnsStr, RefineSourceToShow(req.src, req.dst.Addr()), RefineAddrPortToShow(dialArgument.Target))
		} else {
			log.WithFields(fields).Infof("[DNS] %v <-> %v Reject with empty answer", RefineSourceToShow(req.src, req.dst.Addr()), RefineAddrPortToShow(dialArgument.Target))
		}
	}
}

func (c *DnsController) checkDomainBitmap(qname string) (domainBitmap [32]uint32, allZero bool, shouldUpdateLookupCache bool) {
	bitmapSlice := c.matchBitmap(qname)
	copy(domainBitmap[:], bitmapSlice)
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

func (c *DnsController) updateLookupCache(qname string, domainBitmap [32]uint32, allZero bool, ips []netip.Addr, ttl time.Duration) error {
	if len(ips) == 0 {
		return nil
	}
	lookupTTL := max(ttl, c.minSniffingTtl)
	c.mu.Lock()
	defer c.mu.Unlock()

	for _, ip := range ips {
		if _, ok := c.deadlineTimers[qname]; !ok {
			c.deadlineTimers[qname] = make(map[netip.Addr]*time.Timer)
		}
		if timer, ok := c.deadlineTimers[qname][ip]; ok {
			timer.Reset(lookupTTL)
			continue
		}
		if !allZero {
			if err := c.newLookupCache(ip, domainBitmap); err != nil {
				return err
			}
			common.CoreIpDomainBitmap.Inc()
		}
		c.deadlineTimers[qname][ip] = time.AfterFunc(lookupTTL, func() {
			c.mu.Lock()
			defer c.mu.Unlock()
			if !allZero {
				if err := c.lookupCacheTimeout(ip, domainBitmap); err == nil {
					common.CoreIpDomainBitmap.Dec()
				}
			}
			delete(c.deadlineTimers[qname], ip)
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
	if domainBitmap, allZero, shouldUpdate := c.checkDomainBitmap(qname); shouldUpdate {
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

func (c *DnsController) dialSend(data []byte, upstream *dns.Upstream, dialArg *dialArgument, queryInfo queryInfo) (dnsResponseData, error) {
	cacheKey := dnsCacheKey{queryInfo: queryInfo, outbound: dialArg.Outbound}
	// Lookup Cache
	if c.enableCache {
		if cache := c.dnsCache.Get(cacheKey); cache != nil {
			c.dnsCache.Used(cacheKey, cache)
			respData, expired := CopyResponseFromCache(cache)
			if expired {
				dataCopy := pool.GetBuffer(len(data))
				copy(dataCopy, data)
				go func(d []byte, arg dialArgument) {
					defer pool.PutBuffer(d)
					// Refresh cache asynchronously.
					if _, _, err := c.singleFlightForwardDNS(cacheKey, d, upstream, &arg); err != nil {
						log.Warnf("failed to refresh dns cache for %v: %+v", cacheKey, err)
					}
				}(dataCopy, *dialArg)
			}
			if log.IsLevelEnabled(log.DebugLevel) {
				log.WithFields(log.Fields{
					"answer": FormatDnsRsc(respData),
				}).Debugf("UDP(DNS) <-> Cache: %v %v", queryInfo.qname, queryInfo.qtype)
			}
			return dnsResponseData{respData: respData, fromPool: true, isNew: cache.IsNew}, nil
		}
	}
	// Pending for the same lookup.
	respData, isLeader, err := c.singleFlightForwardDNS(cacheKey, data, upstream, dialArg)
	dnsResp := dnsResponseData{isNew: true}
	if respData != nil {
		if isLeader {
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
	return dnsResp, err
}

func (c *DnsController) singleFlightForwardDNS(
	cacheKey dnsCacheKey, data []byte, upstream *dns.Upstream, dialArgument *dialArgument) ([]byte, bool, error) {
	isLeader := false
	v, err, _ := c.singleFlightGroup.Do(cacheKey.String(), func() (any, error) {
		isLeader = true
		var forwarder DnsForwarder
		key := dnsForwarderKey{upstream: upstream.String(), dialArgument: *dialArgument}
		// get forwarder from cache
		value, ok := c.dnsForwarderCache.Load(key)
		if ok {
			forwarder = value.(DnsForwarder)
		} else {
			var err error
			forwarder, err = newDnsForwarder(upstream, *dialArgument)
			if err != nil {
				return nil, err
			}
			// Try to store the new forwarder, but use LoadOrStore to handle concurrent creation
			actualValue, _ := c.dnsForwarderCache.LoadOrStore(key, forwarder)
			forwarder = actualValue.(DnsForwarder)
		}

		r, err := forwarder.ForwardDNS(data)
		if err != nil {
			return nil, err
		}

		rcode := dnsRcode(r)

		if log.IsLevelEnabled(log.DebugLevel) {
			log.WithFields(log.Fields{
				"qname": cacheKey.qname,
				"qtype": cacheKey.qtype,
				"rcode": rcode,
				"ans":   FormatDnsRsc(r),
			}).Debugf("Got DNS response")
		}

		// TODO: 细分日志
		if !dnsResponse(r) {
			return nil, oops.Errorf("DNS message response flag is unset")
		}
		if !isDnsResponseValid(r) {
			log.WithFields(log.Fields{
				"qname": cacheKey.qname,
				"qtype": cacheKey.qtype,
				"rcode": rcode,
				"ans":   FormatDnsRsc(r),
			}).Tracef("Not a valid DNS response")
			return r, nil
		}

		if c.enableCache {
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
			c.UpdateDnsCacheTtl(cacheKey, r)
		}
		return r, nil
	})
	if v != nil {
		return v.([]byte), isLeader, err
	}
	return nil, isLeader, err
}

func (c *DnsController) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()

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
