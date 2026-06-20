/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package dialer

import (
	"context"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"path"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/daeuniverse/dae/common"
	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/common/netutils"
	"github.com/daeuniverse/outbound/pkg/fastrand"
	"github.com/daeuniverse/outbound/pool"
	dnsmessage "github.com/miekg/dns"
	log "github.com/sirupsen/logrus"
)

const (
	RetryCount    = 3
	RetryInterval = 5 * time.Second
)

func (d *Dialer) Alive() bool {
	return d.Dialer.Alive() && d.alive.Load()
}

func (d *Dialer) Supported(networkTypeIndex int) bool {
	return d.supported.Load()&(1<<networkTypeIndex) != 0
}

func (d *Dialer) setSupportedBit(i int, val bool) {
	mask := uint32(1) << i
	for {
		old := d.supported.Load()
		var new_ uint32
		if val {
			new_ = old | mask
		} else {
			new_ = old &^ mask
		}
		if old == new_ || d.supported.CompareAndSwap(old, new_) {
			return
		}
	}
}

func parseIp46FromList(ip []string) (ip46 netutils.Ip46, err error) {
	for _, ip := range ip {
		addr, err := netip.ParseAddr(ip)
		if err != nil {
			return ip46, common.Wrap(err, "invalid ip address")
		}
		if addr.Is4() || addr.Is4In6() {
			ip46.Ip4 = addr
		} else if addr.Is6() {
			ip46.Ip6 = addr
		}
		if ip46.Ip4.IsValid() && ip46.Ip6.IsValid() {
			break
		}
	}
	return ip46, nil
}

type TcpCheckOption struct {
	Url *netutils.URL
	netutils.Ip46
	Method string
}

func ParseTcpCheckOption(rawURL []string, method string) (opt *TcpCheckOption, err error) {
	if method == "" {
		method = http.MethodGet
	}
	if len(rawURL) == 0 {
		return nil, common.Errf("ParseTcpCheckOption: bad format: empty")
	}
	u, err := url.Parse(rawURL[0])
	if err != nil {
		return nil, err
	}
	var ip46 netutils.Ip46
	if len(rawURL) > 1 {
		ip46, err = parseIp46FromList(rawURL[1:])
		if err != nil {
			return nil, common.Wrap(err, "ParseTcpCheckOption: failed to parse ip from list")
		}
	} else {
		ip46, err = netutils.ParseOrResolveIp46(u.Hostname())
		if err != nil {
			return nil, common.Wrap(err, "ParseTcpCheckOption: failed to resolve ip for %v", u.Hostname())
		}
		if !ip46.IsValid() {
			return nil, common.Errf("ResolveIp46: no valid ip for %v", u.Hostname())
		}
	}
	return &TcpCheckOption{
		Url:    &netutils.URL{URL: u},
		Ip46:   ip46,
		Method: method,
	}, nil
}

type CheckDnsOption struct {
	DnsHost string
	DnsPort uint16
	netutils.Ip46
}

func ParseCheckDnsOption(dnsHostPort []string) (opt *CheckDnsOption, err error) {
	if len(dnsHostPort) == 0 {
		return nil, common.Errf("ParseCheckDnsOption: bad format: empty")
	}

	host, _port, err := net.SplitHostPort(dnsHostPort[0])
	if err != nil {
		return nil, common.Wrap(err, "ParseCheckDnsOption: failed to split host and port")
	}
	port, err := strconv.ParseUint(_port, 10, 16)
	if err != nil {
		return nil, common.Errf("bad port: %v", err)
	}
	var ip46 netutils.Ip46
	if len(dnsHostPort) > 1 {
		ip46, err = parseIp46FromList(dnsHostPort[1:])
		if err != nil {
			return nil, common.Wrap(err, "ParseCheckDnsOption: failed to parse ip from list")
		}
	} else {
		ip46, err = netutils.ParseOrResolveIp46(host)
		if err != nil {
			return nil, common.Wrap(err, "ParseCheckDnsOption: failed to resolve ip for %v", host)
		}
		if !ip46.IsValid() {
			return nil, common.Errf("ResolveIp46: no valid ip for %v", host)
		}
	}
	return &CheckDnsOption{
		DnsHost: host,
		DnsPort: uint16(port),
		Ip46:    ip46,
	}, nil
}

type TcpCheckOptionRaw struct {
	opt    *TcpCheckOption
	mu     sync.Mutex
	Raw    []string
	Method string
}

func (c *TcpCheckOptionRaw) Option() (opt *TcpCheckOption, err error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.opt == nil {
		tcpCheckOption, err := ParseTcpCheckOption(c.Raw, c.Method)
		if err != nil {
			return nil, fmt.Errorf("failed to parse tcp_check_url: %w", err)
		}
		c.opt = tcpCheckOption
	}
	return c.opt, nil
}

type CheckDnsOptionRaw struct {
	opt *CheckDnsOption
	mu  sync.Mutex
	Raw []string
}

func (c *CheckDnsOptionRaw) Option() (opt *CheckDnsOption, err error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.opt == nil {
		udpCheckOption, err := ParseCheckDnsOption(c.Raw)
		if err != nil {
			return nil, fmt.Errorf("failed to parse tcp_check_url: %w", err)
		}
		c.opt = udpCheckOption
	}
	return c.opt, nil
}

type CheckOption struct {
	networkType *common.NetworkType
	CheckFunc   func() (ok bool, err error)
}

// // createTcpCheckFunc 创建TCP检查函数
// func (d *Dialer) createHttpCheckFunc(ipVersion consts.IpVersionStr, network string) func(typ *NetworkType) (ok bool, err error) {
// 	return func(typ *NetworkType) (ok bool, err error) {
// 		opt, err := d.TcpCheckOptionRaw.Option()
// 		if err != nil {
// 			return false, err
// 		}

// 		var ip netip.Addr
// 		switch ipVersion {
// 		case consts.IpVersionStr_4:
// 			ip = opt.Ip4
// 		case consts.IpVersionStr_6:
// 			ip = opt.Ip6
// 		}

// 		if !ip.IsValid() {
// 			log.WithFields(log.Fields{
// 				"link":    d.TcpCheckOptionRaw.Raw,
// 				"dialer":  d.Name,
// 				"network": typ.String(),
// 			}).Debugln("Skip check due to no DNS record.")
// 			return false, nil
// 		}

// 		return d.HttpCheck(opt.Url, ip, opt.Method, network)
// 	}
// }

// checkFunc 创建DNS检查函数
// TODO: Context 应该随情况生成, 而非传入
// TODO: 为什么不直接编写一个 CheckFUnc
func checkFunc(d *Dialer, server string, network string, data []byte) func() (ok bool, err error) {
	return func() (ok bool, err error) {
		return netutils.DnsCheck(d, server, network, data)
	}
}

func (d *Dialer) createCheckOptions() []*CheckOption {
	msg := dnsmessage.Msg{MsgHdr: dnsmessage.MsgHdr{RecursionDesired: true}}
	msg.SetQuestion(common.CanonicalName(consts.UdpCheckLookupHost), dnsmessage.TypeA)
	var newMsgData = func() []byte {
		msg.Id = uint16(fastrand.Intn(math.MaxUint16 + 1))
		d, _ := msg.Pack()
		return d
	}
	server4 := ""
	server6 := ""
	opt, err := d.CheckDnsOptionRaw.Option()
	if err == nil {
		if opt.Ip4.IsValid() {
			server4 = netip.AddrPortFrom(opt.Ip4, opt.DnsPort).String()
		}
		if opt.Ip6.IsValid() {
			server6 = netip.AddrPortFrom(opt.Ip6, opt.DnsPort).String()
		}
	}

	return []*CheckOption{
		// 优先 TCP, 因为 TCP 可以避免长时间占用 NAT 端口
		// TODO: UDP?
		{
			networkType: common.NETWORK_TCP6,
			CheckFunc:   checkFunc(d, server6, "tcp", newMsgData()),
		},
		{
			networkType: common.NETWORK_TCP4,
			CheckFunc:   checkFunc(d, server4, "tcp", newMsgData()),
		},
		{
			networkType: common.NETWORK_UDP6,
			CheckFunc:   checkFunc(d, server6, "udp", newMsgData()),
		},
		{
			networkType: common.NETWORK_UDP4,
			CheckFunc:   checkFunc(d, server4, "udp", newMsgData()),
		},
	}
}

func (d *Dialer) ActivateCheck() {
	if len(d.registeredDialerGroups) == 0 {
		return
	}

	if !d.needAliveState || d.checkActivated {
		return
	}
	d.checkActivated = true

	CheckOpts := d.createCheckOptions()

	go func() {
		// at startup, check all network types to determine which are supported
		done := d.checkCtx.Done()
		var checkOpt *CheckOption
		for range 3 {
			checkOpt = d.runInitialCheck(CheckOpts)
			if checkOpt != nil {
				break
			}
			select {
			case <-done:
				return
			case <-time.After(5 * time.Second):
			}
		}
		if checkOpt == nil {
			return
		}
		// after startup, only run check on one network type
		select {
		case <-done:
			return
		default:
		}
		go d.startCheckTicker()
		go d.runCheckLoop(checkOpt)
	}()
}

func (d *Dialer) ReactivateCheck() {
	if len(d.registeredDialerGroups) == 0 || !d.needAliveState {
		return
	}
	if d.checkActivated {
		d.stopCheck()
		d.checkActivated = false
		d.checkCtx, d.checkCancel = context.WithCancel(context.Background())
	}
	d.ActivateCheck()
}

func (d *Dialer) startCheckTicker() {
	// Sleep to avoid avalanche.
	time.Sleep(time.Duration(fastrand.Int63n(int64(d.CheckInterval))))
	d.tickerMu.Lock()
	d.ticker = time.NewTicker(d.CheckInterval)
	ticker := d.ticker
	d.tickerMu.Unlock()
	done := d.checkCtx.Done()
	for {
		select {
		case <-done:
			return
		case t := <-ticker.C:
			select {
			case <-done:
				return
			case d.checkCh <- t:
			}
		}
	}
}

// Manually start check.
func (d *Dialer) NotifyCheck() {
	select {
	case <-d.checkCtx.Done():
		return
	// If fail to push elem to chan, the check is in process.
	case d.checkCh <- time.Now():
	default:
	}
}

func (d *Dialer) runCheckLoop(checkOpt *CheckOption) {
	done := d.checkCtx.Done()
	for {
		select {
		case <-done:
			return
		case <-d.checkCh:
			didUpdate := false
			for i := 0; i < RetryCount; i++ {
				if i > 0 {
					time.Sleep(RetryInterval)
				}
				if !d.Alive() {
					d.NotifyStatusChange()
					if err := d.Connect(); err != nil {
						continue
					}
				}
				ok, latency, err := d.Check(checkOpt)
				d.Update(ok, latency, checkOpt.networkType, err)
				didUpdate = true
				if ok {
					break
				}
			}
			if !didUpdate {
				d.Update(false, 0, checkOpt.networkType,
					common.Errf("connect failed after %d retries", RetryCount))
			}
			// Cleanup channel to avoid consecutive checks.
			select {
			case <-d.checkCh:
			default:
			}
		}
	}
}

func (d *Dialer) runInitialCheck(checkOpts []*CheckOption) (opt *CheckOption) {
	defer d.NotifyStatusChange()

	d.supported.Store(0)

	var wg sync.WaitGroup
	var latency [4]time.Duration
	var err [4]error
	if !d.Alive() {
		if err := d.Connect(); err != nil {
			log.WithFields(log.Fields{
				"node": d.Name,
			}).Errorf("Failed to connect: %v", err)
			d.Update(false, 0, nil, err)
			return nil
		}
	}
	for _, opt := range checkOpts {
		i := common.NetworkTypeToIndex(opt.networkType)
		wg.Go(func() {
			ok, lat, e := d.Check(opt)
			d.setSupportedBit(i, ok)
			latency[i] = lat
			err[i] = e
			if log.IsLevelEnabled(log.InfoLevel) {
				if ok {
					log.WithFields(log.Fields{
						"network": opt.networkType.String(),
						"node":    d.Name,
						"last":    latency[i].Truncate(time.Millisecond).String(),
					}).Infoln("Inital Connectivity Check")
				} else {
					log.WithFields(log.Fields{
						"network": opt.networkType.String(),
						"node":    d.Name,
					}).Infof("Inital Connectivity Check Failed: %v\n", err[i])
				}
			}
		})
	}
	wg.Wait()
	for _, opt := range checkOpts {
		i := common.NetworkTypeToIndex(opt.networkType)
		if ok := d.Supported(i); ok {
			d.Update(ok, latency[i], opt.networkType, err[i])
			return opt
		}
	}
	return nil
}

func (d *Dialer) RegisterDialerGroup(g DialerGroup) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.registeredDialerGroups[g]++
	d.Latencies10[g] = NewLatenciesN(10)
	d.MovingAverage[g] = 0
}

func (d *Dialer) UnregisterDialerGroup(g DialerGroup) {
	d.mu.Lock()
	defer d.mu.Unlock()
	delete(d.registeredDialerGroups, g)
	delete(d.Latencies10, g)
	delete(d.MovingAverage, g)
}

// ResetLatency clears Latencies10 and MovingAverage for every DialerGroup this
// dialer is currently registered in. It is intended for the update-sub recycle
// path: when a dialer is reused across an update-sub and was previously
// failing, accumulated TimeoutPenalty samples would otherwise keep dragging
// the moving average up after the node recovers. Resets in place; the dialer's
// ticker, alive state, and underlying connection are untouched.
func (d *Dialer) ResetLatency() {
	d.mu.Lock()
	defer d.mu.Unlock()
	for g := range d.registeredDialerGroups {
		d.Latencies10[g] = NewLatenciesN(10)
		d.MovingAverage[g] = 0
	}
}

func (d *Dialer) NotifyStatusChange() {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.notifyStatusChangeLocked()
}

// notifyStatusChangeLocked must be called with d.mu held.
func (d *Dialer) notifyStatusChangeLocked() {
	for g := range d.registeredDialerGroups {
		g.NotifyStatusChange(d)
	}
}

// ReportUnavailable 意味着在测速之外, Dialer 似乎不可用了
func (d *Dialer) ReportUnavailable() {
	if !d.Alive() {
		d.NotifyStatusChange()
	}
	d.NotifyCheck()
}

func (d *Dialer) Update(ok bool, latency time.Duration, networkType *common.NetworkType, err error) {
	if ok {
		maxTimeoutPenalty := time.Duration(0)
		for g := range d.registeredDialerGroups {
			if p := g.GetTimeoutPenalty(); p > maxTimeoutPenalty {
				maxTimeoutPenalty = p
			}
		}
		if latency > maxTimeoutPenalty && maxTimeoutPenalty > 0 {
			ok = false
		}
	}
	oldAlive := d.alive.Load()
	d.alive.Store(ok)
	d.mu.Lock()
	for g := range d.registeredDialerGroups {
		if !ok {
			penalty := g.GetTimeoutPenalty()
			if penalty > 0 {
				latency = penalty
			}
		}
		alpha := g.GetEmaAlpha()
		if d.MovingAverage[g] == 0 {
			d.MovingAverage[g] = latency
		} else {
			d.MovingAverage[g] = time.Duration(float64(d.MovingAverage[g])*(1-alpha) + float64(latency)*alpha)
		}
		d.Latencies10[g].AppendLatency(latency)

		var logLevel log.Level
		if ok {
			if oldAlive {
				logLevel = log.DebugLevel
			} else {
				logLevel = log.InfoLevel
			}
		} else {
			if oldAlive {
				logLevel = log.WarnLevel
			} else {
				logLevel = log.InfoLevel
			}
		}
		if !log.IsLevelEnabled(logLevel) {
			continue
		}

		if ok {
			avg, _ := d.Latencies10[g].AvgLatency()
			fields := log.Fields{
				"node":    d.Name,
				"last":    latency.Truncate(time.Millisecond).String(),
				"avg_10":  avg.Truncate(time.Millisecond),
				"mov_avg": d.MovingAverage[g].Truncate(time.Millisecond),
			}
			if networkType != nil {
				fields["network"] = networkType.String()
			}
			if oldAlive {
				log.WithFields(fields).Debugln("Connectivity Check")
			} else {
				log.WithFields(fields).Infoln("Connectivity Check")
			}
		} else {
			fields := log.Fields{
				"node": d.Name,
			}
			if networkType != nil {
				fields["network"] = networkType.String()
			}
			if oldAlive {
				log.WithFields(fields).Warnf("Connectivity Check Failed: %v", err)
			} else {
				log.WithFields(fields).Infof("Connectivity Check Failed: %v", err)
			}
		}
	}
	// Notify all registered groups once after all statistics are updated
	d.notifyStatusChangeLocked()
	d.mu.Unlock()

	// Dialer just became not alive; abort all connections.
	if oldAlive && !ok {
		d.AbortConns()
	}
}

func (d *Dialer) Check(opts *CheckOption) (ok bool, latency time.Duration, err error) {
	start := time.Now()
	if ok, err = opts.CheckFunc(); ok {
		// Calc latency.
		latency = time.Since(start)
	} else {
		if err == nil {
			err = common.Errf("check func not working")
		} else if strings.HasSuffix(err.Error(), "network is unreachable") { // Append timeout if there is any error or unexpected status code.
			err = common.Errf("network is unreachable")
		} else if strings.HasSuffix(err.Error(), "no suitable address found") ||
			strings.HasSuffix(err.Error(), "non-IPv4 address") {
			err = common.Errf("IPv%v is not supported", opts.networkType.IpVersion)
		}
	}
	return
}

func (d *Dialer) HttpCheck(u *netutils.URL, ip netip.Addr, method string, network string) (ok bool, err error) {
	// HTTP(S) check.
	if method == "" {
		method = http.MethodGet
	}
	cli := http.Client{
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, network, addr string) (c net.Conn, err error) {
				// Force to dial "ip".
				// TODO: 对于开了 sniff 的节点来说, 这仍然可能导致测得错误的连接性
				return d.Dialer.DialContext(ctx, network, net.JoinHostPort(ip.String(), u.Port()))
			},
		},
	}
	ctx, cancel := context.WithTimeout(context.TODO(), consts.DefaultDialTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, method, u.String(), nil)
	if err != nil {
		return false, err
	}
	resp, err := cli.Do(req)
	if err != nil {
		var netErr net.Error
		if errors.As(err, &netErr); netErr.Timeout() {
			err = fmt.Errorf("timeout")
		}
		return false, err
	}
	defer resp.Body.Close()
	// Judge the status code.
	if page := path.Base(req.URL.Path); strings.HasPrefix(page, "generate_") {
		if strconv.Itoa(resp.StatusCode) != strings.TrimPrefix(page, "generate_") {
			b, _ := io.ReadAll(resp.Body)
			if log.IsLevelEnabled(log.DebugLevel) {
				buf := pool.PooledBuffer{}
				defer buf.Reset()
				_ = resp.Request.Write(&buf)
				log.Debugln(buf.String(), "Resp: ", string(b))
			}
			return false, fmt.Errorf("unexpected status code: %v", resp.StatusCode)
		}
		return true, nil
	} else {
		if resp.StatusCode < 200 || resp.StatusCode >= 500 {
			return false, fmt.Errorf("bad status code: %v", resp.StatusCode)
		}
		return true, nil
	}
}
