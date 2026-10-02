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
	"github.com/daeuniverse/outbound/netproxy"
	"github.com/daeuniverse/outbound/pkg/fastrand"
	"github.com/daeuniverse/outbound/pool"
	dnsmessage "github.com/miekg/dns"
	log "github.com/sirupsen/logrus"
)

const (
	RetryCount    = 3
	RetryInterval = 5 * time.Second

	// initialCheckRounds bounds how many full four-network-type rounds the
	// first activation runs before it gives up on discovering a usable
	// network type.
	initialCheckRounds = 3

	// defaultInitialCheckRetryInterval is the pause between discovery rounds. It is
	// a default, not a package-level knob: tests shorten it per dialer through
	// Dialer.checkRetryInterval, which is set before the check goroutine starts and
	// therefore needs no synchronisation.
	defaultInitialCheckRetryInterval = 5 * time.Second
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
	// Hand the context to the goroutines instead of letting them re-read the
	// field: ReactivateCheck swaps it, so a superseded ticker waking from its
	// jitter sleep would otherwise adopt the new context and install a second
	// ticker alongside the new chain's.
	ctx := d.checkCtx
	go d.startCheckTicker(ctx)
	go d.runCheckLoop(ctx, d.createCheckOptions())
}

// runCheckLoop is the dialer's single check goroutine. It runs two phases and
// returns only when the dialer's check context is cancelled:
//
//  1. Discovery: probe every network type until one of them passes, retrying
//     the full round until it does. A node that is merely unreachable while the
//     daemon starts (WAN not up yet, or its probe server momentarily blocked)
//     therefore recovers on its own instead of staying excluded.
//  2. Steady state: keep checking the network type that worked.
//
// Keeping both phases in one goroutine is what makes the lifecycle simple: an
// earlier split (one goroutine discovering, then handing over to a second one)
// needed a running flag, a generation counter and a handover flag to tell a
// live chain from a vanished one, and NotifyCheck rebuilt the chain whenever
// that bookkeeping momentarily disagreed. Here "the chain is running" is
// simply "this goroutine has not returned".
func (d *Dialer) runCheckLoop(ctx context.Context, checkOpts []*CheckOption) {
	d.runCheckLoopWith(ctx, checkOpts, RetryCount, RetryInterval)
}

// runCheckLoopWith is runCheckLoop with an explicit probe-retry budget: a failed
// steady-state probe is retried retryCount times, spaced by retryInterval,
// before the dialer is judged dead for that network type and discovery runs
// again. Tests pass a short budget instead of waiting out RetryInterval.
func (d *Dialer) runCheckLoopWith(ctx context.Context, checkOpts []*CheckOption, retryCount int, retryInterval time.Duration) {
	done := ctx.Done()
	log.WithFields(log.Fields{"node": d.Name}).Infoln("Connectivity check started")

	// One timer is reused by every discovery round: time.After inside the loop
	// would allocate a fresh timer on every retry.
	retryTimer := time.NewTimer(d.checkRetryInterval)
	defer retryTimer.Stop()

	// Discovery and steady state alternate: discovery probes every network type
	// and picks one, steady state checks that one, and a sustained failure of it
	// sends the loop back to discovery.
	for {
		// A probe is expected to return: every dialer must honour its context
		// (netproxy.Dialer's contract). If discovery has not finished after three
		// check intervals, say so instead of going silent — a hung probe is
		// otherwise indistinguishable from "no check ever ran".
		slowWarn := time.AfterFunc(3*d.CheckInterval, func() {
			log.WithFields(log.Fields{
				"node":   d.Name,
				"waited": (3 * d.CheckInterval).String(),
			}).Warnln("Connectivity check is still running: a probe may be stuck ignoring its context")
		})
		// Phase 1: discovery. Probe every network type until one of them passes,
		// retrying the full round until it does — a dialer that is merely
		// unreachable while the daemon starts (WAN not up yet, or its probe server
		// momentarily blocked) therefore recovers on its own instead of staying
		// excluded. Only cancellation of the dialer's context ends this phase.
		var checkOpt *CheckOption
		for {
			var checkErr error
			checkOpt, checkErr = d.runInitialCheck(checkOpts)
			if checkOpt != nil {
				break
			}
			if checkErr == nil {
				checkErr = common.Errf("no usable network type after %d initial check rounds", initialCheckRounds)
			}
			// runInitialCheck only calls Update for a network type that passed, so
			// correct the liveness state explicitly; a later successful round lands
			// Update(true) through runInitialCheck itself.
			d.Update(false, 0, nil, checkErr)
			log.WithFields(log.Fields{
				"node":  d.Name,
				"error": checkErr.Error(),
			}).Warnln("Initial connectivity check found no usable network type; retrying the full discovery")
			// Wait out the rest of the retry interval before the next round. The
			// timer was armed before this round, so a round that already took longer
			// than the interval returns here immediately instead of adding another
			// one on top of it.
			select {
			case <-done:
				slowWarn.Stop()
				log.WithFields(log.Fields{"node": d.Name}).Infoln("Connectivity check stopped before it found a network type")
				return
			case <-retryTimer.C:
			}
			retryTimer.Reset(d.checkRetryInterval)
		}
		slowWarn.Stop()
		log.WithFields(log.Fields{
			"node":    d.Name,
			"network": checkOpt.networkType.String(),
		}).Infoln("Connectivity check entering steady state")

		// Steady state: check the network type that discovery confirmed. If it
		// stops working, leave the loop and run discovery again — that is the
		// only way the support matrix (and noIpv6) are refreshed and the only
		// way the dialer can come back on another network type that still works.
		//
		// TODO: 是否应该在每个周期也探测其它 supported 类型？好处是能在 metrics
		// 中看到未选中类型的延迟，代价是每节点每周期最多 4 次探测。另外，udp 53能通不一定udp 443也能通。
	steady:
		for {
			select {
			case <-done:
				log.WithFields(log.Fields{"node": d.Name}).Infoln("Steady-state check loop stopped")
				return
			case <-d.checkCh:
				// Probe retries. A failed attempt must NOT flip the dialer
				// not-alive while retries remain: the retry loop exists to ride
				// out transient blips, and an eager flip (the old behavior)
				// defeated that — a single lost probe flipped the eBPF
				// connectivity map and downgraded the whole group's flows for
				// one interval. Failed attempts are therefore only accumulated
				// here; Update(false) lands once after the loop is exhausted.
				// Success lands immediately: recovery should propagate ASAP.
				checkPassed := false
				var lastErr error
				for i := range retryCount {
					if i > 0 {
						time.Sleep(retryInterval)
					}
					ok, latency, err := d.Check(checkOpt)
					if ok {
						d.Update(ok, latency, checkOpt.networkType, err)
						checkPassed = true
						break
					}
					lastErr = err
					// A port-hopping link (hysteria2) may have lost its probe on
					// a port that is blocked or lossy. Re-roll the endpoint port
					// for the next attempt instead of retrying the same one; the
					// QUIC connection is kept, so this costs no handshake.
					if i < retryCount-1 && hopPortOnFailure(d.Dialer) && log.IsLevelEnabled(log.DebugLevel) {
						log.WithFields(log.Fields{
							"node": d.Name,
						}).Debugln("Port hop after a failed check")
					}
				}
				// Cleanup channel to avoid consecutive checks.
				select {
				case <-d.checkCh:
				default:
				}
				if checkPassed {
					continue
				}
				d.Update(false, 0, checkOpt.networkType,
					common.Errf("check failed after %d retries: %v", retryCount, lastErr))
				// The network type steady state was checking looks dead for
				// good. Drop the latency history so the group series does not
				// blend this type's samples with the type discovery picks next
				// (TCP handshakes and UDP probes differ by an order of
				// magnitude), then re-run discovery. Recovery from here is
				// handled by discovery, which reconnects if needed before
				// probing every network type.
				d.ResetLatency()
				log.WithFields(log.Fields{
					"node":    d.Name,
					"network": checkOpt.networkType.String(),
					"error":   lastErr,
				}).Warnln("Connectivity check failed; re-running discovery to refresh the supported network types")
				break steady
			}
		}
	}
}

func (d *Dialer) runInitialCheck(checkOpts []*CheckOption) (opt *CheckOption, checkErr error) {
	defer d.NotifyStatusChange()

	d.supported.Store(0)

	var wg sync.WaitGroup
	var latency [4]time.Duration
	var errs [4]error
	if !d.Alive() {
		if err := d.connectOnce(); err != nil {
			log.WithFields(log.Fields{
				"node": d.Name,
			}).Errorf("Failed to connect: %v", err)
			d.Update(false, 0, nil, err)
			return nil, err
		}
	}
	for _, opt := range checkOpts {
		i := common.NetworkTypeToIndex(opt.networkType)
		wg.Go(func() {
			ok, lat, e := d.Check(opt)
			d.setSupportedBit(i, ok)
			latency[i] = lat
			errs[i] = e
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
					}).Infof("Inital Connectivity Check Failed: %v\n", errs[i])
				}
			}
		})
	}
	wg.Wait()
	// A dialer that fails both IPv6 checks cannot proxy IPv6 traffic at all.
	// Mark it so DNS AAAA requests through it are rejected, keeping clients
	// on IPv4 instead of routing IPv6 to a different (IPv6-capable) node.
	d.noIpv6.Store(
		!d.Supported(common.NetworkTypeToIndex(common.NETWORK_TCP6)) &&
			!d.Supported(common.NetworkTypeToIndex(common.NETWORK_UDP6)))
	for _, opt := range checkOpts {
		i := common.NetworkTypeToIndex(opt.networkType)
		if ok := d.Supported(i); ok {
			// The first pass above established the connection; for TCP+mux
			// protocols (e.g. anytls) its latency includes the TCP+TLS
			// handshake, which over-penalizes them against UDP/QUIC protocols
			// (e.g. hysteria2) whose handshake is ~free. Re-check the same
			// network type once more: the connection is now warm (reused from
			// the dialer's session pool), so the second latency reflects the
			// steady state and is the right seed for the moving average.
			// Alive/support state is still taken from the first pass.
			warmLatency, warmErr := latency[i], errs[i]
			if ok2, lat2, err2 := d.Check(opt); ok2 {
				warmLatency, warmErr = lat2, err2
			} else if log.IsLevelEnabled(log.WarnLevel) {
				log.WithFields(log.Fields{
					"network": opt.networkType.String(),
					"node":    d.Name,
				}).Warnf("Inital Connectivity Check warm re-check failed: %v; falling back to cold latency", err2)
			}
			if log.IsLevelEnabled(log.DebugLevel) {
				log.WithFields(log.Fields{
					"network": opt.networkType.String(),
					"node":    d.Name,
					"cold":    latency[i].Truncate(time.Millisecond).String(),
					"warm":    warmLatency.Truncate(time.Millisecond).String(),
				}).Debugln("Inital Connectivity Check (warm re-check)")
			}
			d.Update(ok, warmLatency, opt.networkType, warmErr)
			return opt, nil
		}
	}
	// No network type worked. Report why so the caller can correct the
	// liveness state; prefer a real probe error over a generic one.
	for _, opt := range checkOpts {
		if e := errs[common.NetworkTypeToIndex(opt.networkType)]; e != nil {
			return nil, e
		}
	}
	return nil, common.Errf("no network type passed the initial connectivity check")
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

func (d *Dialer) startCheckTicker(ctx context.Context) {
	done := ctx.Done()
	// Sleep to avoid avalanche, but stay cancellable: a superseded ticker must
	// not wake up and install itself (and it must not adopt a newer context).
	select {
	case <-done:
		return
	case <-time.After(time.Duration(fastrand.Int63n(int64(d.CheckInterval)))):
	}
	d.tickerMu.Lock()
	ticker := time.NewTicker(d.CheckInterval)
	d.ticker = ticker
	d.tickerMu.Unlock()
	defer func() {
		// We own this ticker: on every exit path it must be stopped and, if we
		// still own the slot, cleared under the mutex so a later stopCheck does
		// not try to stop a ticker that has already been stopped.
		ticker.Stop()
		d.tickerMu.Lock()
		if d.ticker == ticker {
			d.ticker = nil
		}
		d.tickerMu.Unlock()
	}()
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

// NotifyCheck nudges the check goroutine, e.g. after a relay failed through
// this dialer. There is nothing to re-arm: runCheckLoop returns only when the
// dialer is stopped, so an activated dialer always has its goroutine.
func (d *Dialer) NotifyCheck() {
	// If fail to push elem to chan, the check is in process.
	select {
	case d.checkCh <- time.Now():
	default:
	}
}

// connectSingleFlight dedupes concurrent Connect issuers per dialer: a long
// NOT-ALIVE retry cycle overlapping the next tick, or a manual NotifyCheck,
// makes several check loops reach Connect for the same dialer at once — they
// share one in-flight connect instead of stacking handshakes (and, for eager
// protocols like hysteria2, tearing down the tunnel a sibling just
// established). The group is global; the key is the dialer itself.
var connectSingleFlight common.SingleFlight[*Dialer, struct{}, struct{}]

// connectOnce issues Connect at most once per window: concurrent check loops
// (a long NOT-ALIVE retry cycle overlapping the next tick, or a manual
// NotifyCheck) share the single in-flight connect instead of each stacking
// its own handshake — and, for eager protocols like hysteria2, tearing down
// the tunnel a sibling just established. A plain mutex would NOT do: waiters
// pass their !Alive test before blocking, so each queued waiter would still
// issue its own Connect and rebuild in turn.
func (d *Dialer) connectOnce() error {
	_, err, _, _ := connectSingleFlight.Do(d, struct{}{}, func(struct{}) (struct{}, error) {
		return struct{}{}, d.Connect()
	})
	return err
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

	// alive -> not alive no longer aborts immediately: arm a deferred abort
	// that fires one CheckInterval later unless a recovery cancels it (see
	// scheduleAbortConns). Any successful check disarms the timer, so a
	// single flapped check round never kills the connections whose tunnels
	// are actually still up.
	if oldAlive && !ok {
		d.scheduleAbortConns()
	}
	if ok {
		d.cancelAbortConns()
	}
}

// scheduleAbortConns arms the deferred AbortConns: a full CheckInterval must
// pass with the dialer still not alive — i.e. two consecutive check rounds
// failed — before the connections through it are killed. A node that flaps
// briefly and recovers within the window cancels the timer and its live
// connections survive. Retries must not stack timers: an armed timer is
// left alone. A dialer with no CheckInterval configured keeps the legacy
// immediate-abort behavior.
func (d *Dialer) scheduleAbortConns() {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.abortConnsTimer != nil {
		return // already armed
	}
	if d.CheckInterval <= 0 {
		d.AbortConns()
		return
	}
	d.abortConnsTimer = time.AfterFunc(d.CheckInterval, d.abortConnsTimerFired)
}

// abortConnsTimerFired runs one CheckInterval after the first failed check.
// The alive re-check guards the race where recovery landed between the last
// check tick and the fire.
func (d *Dialer) abortConnsTimerFired() {
	d.mu.Lock()
	d.abortConnsTimer = nil
	d.mu.Unlock()
	if d.alive.Load() {
		return
	}
	log.WithFields(log.Fields{
		"node":  d.Name,
		"after": d.CheckInterval,
	}).Warnln("Dialer still not alive after two consecutive check failures; aborting its connections")
	d.AbortConns()
}

// cancelAbortConns disarms a pending deferred abort (the dialer recovered).
func (d *Dialer) cancelAbortConns() {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.abortConnsTimer != nil {
		d.abortConnsTimer.Stop()
		d.abortConnsTimer = nil
	}
}

// PortHopper is implemented by dialers whose endpoint port is drawn from a
// range (hysteria2 port hopping). HopPort re-rolls the port of the live
// connection without reconnecting, and reports whether it did.
type PortHopper interface {
	HopPort() bool
}

// hopPortOnFailure re-rolls a port-hopping dialer's endpoint port after a
// failed probe, so the retry does not land on the same port. Dialers that do
// not hop ports, or that are not connected, report false.
func hopPortOnFailure(dl netproxy.Dialer) bool {
	hopper, ok := dl.(PortHopper)
	if !ok {
		return false
	}
	return hopper.HopPort()
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
		netErr, ok := errors.AsType[net.Error](err)
		if ok && netErr.Timeout() {
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
