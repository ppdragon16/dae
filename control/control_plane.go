/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/bits-and-blooms/bloom/v3"
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/features"
	"github.com/cilium/ebpf/rlimit"
	"github.com/daeuniverse/dae/common"
	"github.com/daeuniverse/dae/common/assets"
	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/common/netutils"
	"github.com/daeuniverse/dae/common/subscription"
	"github.com/daeuniverse/dae/component/dns"
	"github.com/daeuniverse/dae/component/outbound"
	"github.com/daeuniverse/dae/component/outbound/dialer"
	"github.com/daeuniverse/dae/component/routing"
	"github.com/daeuniverse/dae/config"
	"github.com/daeuniverse/dae/pkg/config_parser"
	internal "github.com/daeuniverse/dae/pkg/ebpf_internal"
	D "github.com/daeuniverse/outbound/dialer"
	"github.com/daeuniverse/outbound/pool"
	"github.com/daeuniverse/outbound/protocol/direct"

	"github.com/daeuniverse/outbound/transport/grpc"
	"github.com/daeuniverse/outbound/transport/meek"
	log "github.com/sirupsen/logrus"
)

var (
	LogFileDir string
)

type dnsRouteCacheKey struct {
	upstream *dns.Upstream
	src      netip.Addr
}

type ControlPlane struct {
	core       *controlPlaneCore
	deferFuncs []func() error
	listenIp   string

	// TODO: add mutex?
	outbounds              []*outbound.DialerGroup
	noConnectivityOutbound consts.OutboundIndex
	inConnections          sync.Map

	dnsController *DnsController

	routingMatcher *RoutingMatcher

	ctx    context.Context
	cancel context.CancelFunc

	muRealDomainSet sync.Mutex
	realDomainSet   *bloom.BloomFilter

	wanInterface []string
	lanInterface []string

	dialTargetOverride bool
	rerouteMode        consts.RerouteMode
	sniffingTimeout    time.Duration
	sniffVerifyMode    consts.SniffVerifyMode
	udpSniffPorts      []uint16
	tproxyPortProtect  bool
	soMarkFromDae      uint32

	trafficLogger *TrafficLogger

	outboundRedirects     map[consts.OutboundIndex]consts.OutboundIndex
	muOutboundRedirects   sync.RWMutex
	dnsRouteCache         *common.TimeWheelCache[dnsRouteCacheKey, consts.OutboundIndex]
	dnsRoutingResultCache *common.TimeWheelCache[netip.Addr, *bpfRoutingResult]

	udpTaskPool *UdpTaskPool[netip.AddrPort, emitParam]

	bpfMapJanitor bpfMapJanitor

	// Subscription update support.
	cfgFile         string
	subscriptionDir string
	config          *config.ConfigTrimmed
	inuseDialers    []*dialer.Dialer
	muUpdateSub     sync.Mutex
	UpdatingSub     atomic.Bool

	// Routing update support.
	UpdatingRouting   atomic.Bool
	muUpdateRouting   sync.Mutex
	locationFinder    *assets.LocationFinder
	externGeoDataDirs []string
}

// TODO: 统一 Outbound 中的DNS解析器
// TODO: Hy2 的 mark 支持
// TODO: Connectivity Check Failed 仅将状态变更作为 Warning、
// HandlePkt HandleConn 分割 Route 和 Dial
func NewControlPlane(
	_bpf interface{},
	tagToNodeList map[string][]string,
	groups []config.Group,
	routingA *config.Routing,
	global *config.Global,
	dnsConfig *config.Dns,
	externGeoDataDirs []string,
) (*ControlPlane, error) {
	// TODO: Some users reported that enabling GSO on the client wgrpcould affect the performance of watching YouTube, so we disabled it by default.
	if _, ok := os.LookupEnv("QUIC_GO_DISABLE_GSO"); !ok {
		os.Setenv("QUIC_GO_DISABLE_GSO", "1")
	}

	var err error

	kernelVersion, e := internal.KernelVersion()
	if e != nil {
		return nil, common.Errf("failed to get kernel version: %w", e)
	}
	/// Check linux kernel requirements.
	// Check version from high to low to reduce the number of user upgrading kernel.
	if err := features.HaveProgramHelper(ebpf.SchedCLS, asm.FnLoop); err != nil {
		return nil, common.Errf("%w: your kernel version %v does not support bpf_loop (needed by routing); expect >=%v; upgrade your kernel and try again",
			err,
			kernelVersion.String(),
			consts.BpfLoopFeatureVersion.String())
	}
	if requirement := consts.ChecksumFeatureVersion; kernelVersion.Less(requirement) {
		return nil, common.Errf("your kernel version %v does not support checksum related features; expect >=%v; upgrade your kernel and try again",
			kernelVersion.String(),
			requirement.String())
	}
	if requirement := consts.BpfTimerFeatureVersion; len(global.WanInterface) > 0 && kernelVersion.Less(requirement) {
		return nil, common.Errf("your kernel version %v does not support bind to WAN; expect >=%v; remove wan_interface in config file and try again",
			kernelVersion.String(),
			requirement.String())
	}
	if requirement := consts.SkAssignFeatureVersion; len(global.LanInterface) > 0 && kernelVersion.Less(requirement) {
		return nil, common.Errf("your kernel version %v does not support bind to LAN; expect >=%v; remove lan_interface in config file and try again",
			kernelVersion.String(),
			requirement.String())
	}
	if kernelVersion.Less(consts.BasicFeatureVersion) {
		return nil, common.Errf("your kernel version %v does not satisfy basic requirement; expect >=%v",
			kernelVersion.String(),
			consts.BasicFeatureVersion.String())
	}

	var deferFuncs []func() error

	/// Allow the current process to lock memory for eBPF resources.
	if err = rlimit.RemoveMemlock(); err != nil {
		return nil, common.Errf("rlimit.RemoveMemlock:%v", err)
	}

	/// Init DaeNetns.
	InitDaeNetns()
	if err = InitSysctlManager(); err != nil {
		return nil, err
	}

	if err = GetDaeNetns().Setup(); err != nil {
		return nil, common.Errf("failed to setup dae netns: %w", err)
	}
	pinPath := filepath.Join(consts.BpfPinRoot, consts.AppName)
	if err = os.MkdirAll(pinPath, 0755); err != nil && !os.IsExist(err) {
		if os.IsNotExist(err) {
			log.Warnln("Perhaps you are in a container environment (such as lxc). If so, please use higher virtualization (kvm/qemu).")
		}
		return nil, err
	}

	/// Load pre-compiled programs and maps into the kernel.
	if _bpf == nil {
		log.Infof("Loading eBPF programs and maps into the kernel...")
		log.Infof("The loading process takes about 120MB free memory, which will be released after loading. Insufficient memory will cause loading failure.")
	}
	//var bpf bpfObjects
	var ProgramOptions = ebpf.ProgramOptions{
		KernelTypes: nil,
	}
	if log.IsLevelEnabled(log.PanicLevel) {
		ProgramOptions.LogLevel = ebpf.LogLevelBranch | ebpf.LogLevelStats
		// ProgramOptions.LogLevel = ebpf.LogLevelInstruction | ebpf.LogLevelStats
	}
	collectionOpts := &ebpf.CollectionOptions{
		Maps: ebpf.MapOptions{
			PinPath: pinPath,
		},
		Programs: ProgramOptions,
	}
	var bpf *bpfObjects
	if _bpf != nil {
		if _bpf, ok := _bpf.(*bpfObjects); ok {
			bpf = _bpf
		} else {
			return nil, common.Errf("unexpected bpf type: %T", _bpf)
		}
	} else {
		bpf = new(bpfObjects)
		if err = fullLoadBpfObjects(bpf, &loadBpfOptions{
			PinPath:             pinPath,
			BigEndianTproxyPort: uint32(common.Htons(global.TproxyPort)),
			CollectionOptions:   collectionOpts,
			KernelVersion:       &kernelVersion,
		}); err != nil {
			err = common.Wrap(err, "load eBPF objects")
			if log.IsLevelEnabled(log.PanicLevel) {
				log.Panicf("%+v", err)
			}
			return nil, err
		}
	}
	log.Infof("Loaded eBPF programs and maps")
	core := newControlPlaneCore(
		bpf,
		&kernelVersion,
		_bpf != nil,
	)
	defer func() {
		if err != nil {
			// Flip back.
			core.Flip()
			_ = core.Close()
		}
	}()

	common.InitMetrics()

	/// DialerGroups (outbounds).
	if global.AllowInsecure {
		log.Warnln("AllowInsecure is enabled, but it is not recommended. Please make sure you have to turn it on.")
	}
	option := dialer.NewGlobalOption(global.Trim())

	consts.VerifyRerouteMode(string(global.RerouteMode))
	consts.VerifySniffVerifyMode(string(global.SniffVerifyMode))

	sniffingTimeout := global.SniffingTimeout
	if !global.DialTargetOverride && global.RerouteMode == consts.RerouteMode_None {
		// Sniff is not needed.
		sniffingTimeout = 0
	}

	/// Init DialerGroups.
	var noConnectivityOutbound consts.OutboundIndex
	switch global.NoConnectivityBehavior {
	case "direct":
		noConnectivityOutbound = consts.OutboundDirect
	case "block":
		noConnectivityOutbound = consts.OutboundBlock
	default:
		return nil, common.Errf("invalid no_connectivity_behavior: %v", global.NoConnectivityBehavior)
	}

	_direct, directProperty := D.NewDirectDialer(&option.ExtraOption)
	direct := dialer.NewDialer(_direct, option, &dialer.Property{Property: *directProperty}, false)
	_block, blockProperty := D.NewBlockDialer(&option.ExtraOption, func() { /*Dialer Outbound*/ })
	block := dialer.NewDialer(_block, option, &dialer.Property{Property: *blockProperty}, false)
	outbounds := []*outbound.DialerGroup{
		outbound.NewDialerGroup(option, consts.OutboundDirect.String(),
			[]*dialer.Dialer{direct}, []*dialer.Annotation{{}},
			dialer.DialerSelectionPolicy{
				Policy:     consts.DialerSelectionPolicy_Fixed,
				FixedIndex: 0,
			}, nil),
		outbound.NewDialerGroup(option, consts.OutboundBlock.String(),
			[]*dialer.Dialer{block}, []*dialer.Annotation{{}},
			dialer.DialerSelectionPolicy{
				Policy:     consts.DialerSelectionPolicy_Fixed,
				FixedIndex: 0,
			}, nil),
	}

	// Filter out groups.
	// FIXME: Ugly code here: reset grpc and meek clients manually.
	grpc.CleanGlobalClientConnectionCache()
	meek.CleanGlobalRoundTripperCache()

	dialerSet := outbound.NewDialerSetFromLinks(option, tagToNodeList)
	groupNameRedirects := make(map[string]string)
	for _, group := range groups {
		// Handle redirect: if group has redirect config, ignore filter/policy and use direct dialer with fixed(0).
		if len(group.Redirect) > 0 && group.Name != group.Redirect {
			groupNameRedirects[group.Name] = group.Redirect
			id := uint8(len(outbounds))
			dialerGroup := outbound.NewDialerGroup(
				option,
				group.Name,
				[]*dialer.Dialer{direct},
				[]*dialer.Annotation{{}},
				dialer.DialerSelectionPolicy{Policy: consts.DialerSelectionPolicy_Fixed},
				core.outboundAliveChangeCallback(id, group.Name, global.NoConnectivityTrySniff, noConnectivityOutbound),
			)
			outbounds = append(outbounds, dialerGroup)
			continue
		}
		// Parse policy.
		policy, err := dialer.NewDialerSelectionPolicyFromGroupParam(&group)
		if err != nil {
			return nil, common.Errf("failed to create group %v: %w", group.Name, err)
		}
		// Filter nodes with user given filters.
		dialers, annos, err := dialerSet.FilterAndAnnotate(group.Filter, group.FilterAnnotation, group.NextHop)
		if err != nil {
			return nil, common.Errf(`failed to create group "%v": %w`, group.Name, err)
		}
		// Convert node links to dialers.
		log.Infof(`Group "%v" node list:`, group.Name)
		for _, d := range dialers {
			log.Infoln("\t" + d.Name)
		}
		if len(dialers) == 0 {
			log.Infoln("\t<Empty>")
		}
		groupOption, err := ParseGroupOverrideOption(group, *global.Trim())
		finalOption := option
		if err == nil && groupOption != nil {
			newDialers := make([]*dialer.Dialer, 0)
			for _, d := range dialers {
				newDialer := d.Clone()
				newDialer.GlobalOption = groupOption
				newDialers = append(newDialers, newDialer)
			}
			log.Infof(`Group "%v"'s check option has been override.`, group.Name)
			dialers = newDialers
			finalOption = groupOption
		}
		id := uint8(len(outbounds))
		// Create dialer group and append it to outbounds.
		dialerGroup := outbound.NewDialerGroup(finalOption, group.Name, dialers, annos, *policy,
			core.outboundAliveChangeCallback(id, group.Name, global.NoConnectivityTrySniff, noConnectivityOutbound))
		outbounds = append(outbounds, dialerGroup)
	}
	for fromName, toName := range groupNameRedirects {
		fromIdx, _ := OutboundIndexByName(outbounds, fromName)
		toIdx, _ := OutboundIndexByName(outbounds, toName)
		log.Infof("Outbound redirect: %v (%v) -> %v (%v)", fromName, fromIdx, toName, toIdx)
	}

	// Generate outboundName2Id from outbounds.
	if len(outbounds) > int(consts.OutboundUserDefinedMax) {
		return nil, common.Errf("too many outbounds")
	}
	outboundName2Id := make(map[string]uint8)
	for i, o := range outbounds {
		if _, exist := outboundName2Id[o.Name]; exist {
			return nil, common.Errf("duplicated outbound name: %v", o.Name)
		}
		outboundName2Id[o.Name] = uint8(i)
	}

	/// Node Connectivity Check.
	for _, g := range outbounds {
		deferFuncs = append(deferFuncs, g.Close)
		// Skip connectivity check for redirect groups (they use direct dialer as forwarding).
		if _, isRedirect := groupNameRedirects[g.Name]; isRedirect {
			continue
		}
		for _, d := range g.Dialers {
			// We only activate check of nodes that have a group.
			d.ActivateCheck()
		}
	}

	// Collect all in-use dialers from groups for shutdown cleanup.
	inuseDialers := make([]*dialer.Dialer, 0)
	for _, g := range outbounds {
		inuseDialers = append(inuseDialers, g.Dialers...)
	}

	/// Routing.
	// Apply rules optimizers.
	locationFinder := assets.NewLocationFinder(externGeoDataDirs)
	var rules []*config_parser.RoutingRule
	if rules, err = routing.ApplyRulesOptimizers(routingA.Rules,
		&routing.AliasOptimizer{},
		&routing.DatReaderOptimizer{LocationFinder: locationFinder},
		&routing.MergeAndSortRulesOptimizer{},
		&routing.DeduplicateParamsOptimizer{},
	); err != nil {
		return nil, common.Errf("ApplyRulesOptimizers error:\n%w", err)
	}
	routingA.Rules = nil // Release.
	if log.IsLevelEnabled(log.DebugLevel) {
		var debugBuilder strings.Builder
		for _, rule := range rules {
			debugBuilder.WriteString(rule.String(true, false, false))
			debugBuilder.WriteByte('\n')
		}
		log.Debugf("RoutingA:\n%vfallback: %v\n", debugBuilder.String(), routingA.Fallback)
	}
	// Parse rules and build.
	builder, err := NewRoutingMatcherBuilder(rules, outboundName2Id, bpf, routingA.Fallback, core.ifmgr)
	if err != nil {
		return nil, common.Errf("NewRoutingMatcherBuilder: %w", err)
	}
	if err = builder.BuildKernspace(); err != nil {
		return nil, common.Errf("RoutingMatcherBuilder.BuildKernspace: %w", err)
	}
	routingMatcher, err := builder.BuildUserspace()
	if err != nil {
		return nil, common.Errf("RoutingMatcherBuilder.BuildUserspace: %w", err)
	}

	// Release temporary allocations from rule processing to avoid memory spike.
	runtime.GC()

	var trafficLogger *TrafficLogger
	if global.EnableTrafficLog {
		trafficLogger, err = NewTrafficLogger(filepath.Join(LogFileDir, "traffic.log"), 5*time.Minute)
		if err != nil {
			return nil, common.Errf("NewTrafficLogger: %w", err)
		}
	}

	// New control plane.
	ctx, cancel := context.WithCancel(context.Background())
	plane := &ControlPlane{
		core:                   core,
		deferFuncs:             deferFuncs,
		listenIp:               "0.0.0.0",
		outbounds:              outbounds,
		noConnectivityOutbound: noConnectivityOutbound,
		dnsController:          nil,
		routingMatcher:         routingMatcher,
		ctx:                    ctx,
		cancel:                 cancel,
		muRealDomainSet:        sync.Mutex{},
		realDomainSet:          bloom.NewWithEstimates(2048, 0.001),
		lanInterface:           global.LanInterface,
		wanInterface:           global.WanInterface,
		dialTargetOverride:     global.DialTargetOverride,
		rerouteMode:            global.RerouteMode,
		sniffVerifyMode:        global.SniffVerifyMode,
		sniffingTimeout:        sniffingTimeout,
		udpSniffPorts:          convertUdpSniffPorts(global.UdpSniffPorts),
		tproxyPortProtect:      global.TproxyPortProtect,
		soMarkFromDae:          global.SoMarkFromDae,
		trafficLogger:          trafficLogger,

		dnsRouteCache:         common.NewTimeWheelCache[dnsRouteCacheKey, consts.OutboundIndex](1*time.Hour, 5*time.Second, nil),
		dnsRoutingResultCache: common.NewTimeWheelCache[netip.Addr, *bpfRoutingResult](1*time.Hour, 5*time.Second, nil),
		udpTaskPool:           NewUdpTaskPool[netip.AddrPort, emitParam](AddrPortHash),

		bpfMapJanitor:     newBpfMapJanitor(func() *bpfObjects { return core.bpf }),
		locationFinder:    locationFinder,
		externGeoDataDirs: externGeoDataDirs,
	}
	plane.inuseDialers = inuseDialers
	if err := plane.rebuildOutboundRedirects(groups); err != nil {
		return nil, err
	}
	defer func() {
		if err != nil {
			cancel()
		}
	}()

	/// DNS upstream.
	dnsUpstream, err := dns.New(dnsConfig, &dns.NewOption{
		LocationFinder:          locationFinder,
		UpstreamReadyCallback:   plane.cacheDnsUpstream,
		UpstreamResolverNetwork: "udp",
	}, outboundName2Id)
	if err != nil {
		return nil, err
	}
	// Init immediately to avoid DNS leaking in the very beginning because param control_plane_dns_routing will
	// be set in callback.
	if err = dnsUpstream.CheckUpstreamsFormat(); err != nil {
		return nil, err
	}
	/// Dns controller.
	fixedDomainTtl, err := ParseFixedDomainTtl(dnsConfig.FixedDomainTtl)
	if err != nil {
		return nil, err
	}
	UdpPoolSize = dnsConfig.UdpPoolSize
	UdpPoolTtl = dnsConfig.UdpPoolTtl
	TcpPoolSize = dnsConfig.TcpPoolSize
	TcpPoolTtl = dnsConfig.TcpPoolTtl
	if plane.dnsController, err = NewDnsController(dnsUpstream, &DnsControllerOption{
		MatchBitmap: func(fqdn string, bitmap []uint32) {
			plane.routingMatcher.domainMatcher.MatchDomainBitmapInplace(fqdn, bitmap)
		},
		NewLookupCache: func(ip netip.Addr, domainBitmap *[32]uint32) error {
			// Write mappings into eBPF map:
			// IP record (from dns lookup) -> domain routing
			if err := core.BatchNewDomain(ip, domainBitmap); err != nil {
				return common.Wrap(err, "BatchNewDomain")
			}
			return nil
		},
		LookupCacheTimeout: func(ip netip.Addr, domainBitmap *[32]uint32) error {
			if err := core.BatchRemoveDomain(ip, domainBitmap); err != nil {
				return common.Wrap(err, "BatchRemoveDomain")
			}
			return nil
		},
		BestDialerChooser: plane.chooseBestDnsDialer,
		IpVersionPrefer:   dnsConfig.IpVersionPrefer,
		FixedDomainTtl:    fixedDomainTtl,
		MinSniffingTtl:    dnsConfig.MinSniffingTtl,
		EnableCache:       dnsConfig.EnableCache,
		SniffVerifyMode:   plane.sniffVerifyMode,
	}); err != nil {
		return nil, err
	}
	plane.deferFuncs = append(deferFuncs, plane.dnsController.Close)
	// 规则改变不会使得记录失效, 因为程序仍会访问那个域名, 但我们需要保留记录的条目以便 GC
	if _bpf != nil {
		var key [4]uint32
		var val bpfDomainRouting
		iter := core.bpf.DomainRoutingMap.Iterate()
		for iter.Next(&key, &val) {
			_ = core.bpf.DomainRoutingMap.Delete(&key)
		}
		iter = core.bpf.DomainBumpMap.Iterate()
		for iter.Next(&key, &val) {
			_ = core.bpf.DomainBumpMap.Delete(&key)
		}
	}

	// Wait for that all of the referenced outbounds have tcp4 dialer alive.
	outBoundsToWait := make(map[consts.OutboundIndex]bool)
	for _, rule := range builder.rules {
		outbound := consts.OutboundIndex(rule.Outbound)
		if outbound >= consts.OutboundUserDefinedMin &&
			outbound <= consts.OutboundUserDefinedMax {
			if outbound2, isRedirect := plane.outboundRedirects[outbound]; isRedirect {
				outbound = outbound2
			}
			outBoundsToWait[outbound] = true
		}
	}
	retryCount := 0
	for retryCount < 30 {
		for _, g := range outbounds {
			outboundIndex := consts.OutboundIndex(outboundName2Id[g.Name])
			if _, ok := outBoundsToWait[outboundIndex]; !ok {
				continue
			}
			if _, err := g.Select(common.NETWORK_TCP4); err == nil {
				delete(outBoundsToWait, outboundIndex)
			}
		}
		if len(outBoundsToWait) == 0 {
			break
		}
		time.Sleep(1 * time.Second)
		retryCount++
	}
	if len(outBoundsToWait) > 0 {
		log.Warnf("Outbounds failed to become ready: %v", outBoundsToWait)
	}

	log.Infof("Initialization is completed. Start to Proxying...")
	for i, g := range outbounds {
		if consts.OutboundIndex(i).IsReserved() {
			continue
		}
		g.PrintLatency()
	}

	/// Bind to links. Binding should be advance of dialerGroups to avoid un-routable old connection.
	if err = core.setupExitHandler(); err != nil {
		return nil, common.Errf("failed to setup exit handler: %w", err)
	}
	// Bind to LAN
	if len(global.LanInterface) > 0 {
		if global.AutoConfigKernelParameter {
			_ = SetIpv4forward("1")
			_ = setForwarding("all", consts.IpVersionStr_6, "1")
		}
		global.LanInterface = common.Deduplicate(global.LanInterface)
		for _, ifname := range global.LanInterface {
			core.bindLan(ifname, global.AutoConfigKernelParameter)
		}
	}
	// Bind to WAN
	if len(global.WanInterface) > 0 {
		if err = core.setupSkPidMonitor(); err != nil {
			log.Warnf("%+v", common.Wrap(err, "cgroup2 is not enabled; pname routing cannot be used"))
		}
		if global.EnableLocalTcpFastRedirect {
			if err = core.setupLocalTcpFastRedirect(); err != nil {
				log.Warnf("%+v", common.Wrap(err, "failed to setup local tcp fast redirect"))
			}
		}
		for _, ifname := range global.WanInterface {
			if len(global.LanInterface) > 0 {
				// FIXME: Code is not elegant here.
				// bindLan setting conf.ipv6.all.forwarding=1 suppresses accept_ra=1,
				// thus we set it 2 as a workaround.
				// See https://sysctl-explorer.net/net/ipv6/accept_ra/ for more information.
				if global.AutoConfigKernelParameter {
					acceptRa := sysctl.Keyf("net.ipv6.conf.%v.accept_ra", ifname)
					val, _ := acceptRa.Get()
					if val == "1" {
						_ = acceptRa.Set("2", false)
					}
				}
			}
			core.bindWan(ifname, global.AutoConfigKernelParameter)
		}
	}
	// Bind to dae0 and dae0peer
	if err = core.bindDaens(); err != nil {
		return nil, common.Errf("bindDaens: %w", err)
	}

	return plane, nil
}

func (c *ControlPlane) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	writer := bufio.NewWriter(w)
	defer writer.Flush()

	parts := strings.Split(r.URL.Path, "/")
	cmd := parts[1]
	params := parts[2:]

	switch cmd {
	case "gc":
		runtime.GC()
		fmt.Fprintf(writer, "OK\n")
	case "redirect":
		if r.Method == "GET" {
			if len(params) > 0 {
				http.Error(w, fmt.Sprintf("GET redirect shouldn't have parameters: %v", params), http.StatusBadRequest)
				return
			}
			c.muOutboundRedirects.RLock()
			for i, dg := range c.outbounds {
				if index, exists := c.outboundRedirects[consts.OutboundIndex(i)]; exists {
					fmt.Fprintf(writer, "- %s -> %s\n", dg.Name, c.outbounds[index].Name)
				} else {
					fmt.Fprintf(writer, "- %s\n", dg.Name)
				}
			}
			c.muOutboundRedirects.RUnlock()
			return
		}
		if r.Method == "PUT" {
			if len(params) != 1 {
				http.Error(w, fmt.Sprintf("PUT redirect should have 1 parameter, but got: %v", params), http.StatusBadRequest)
				return
			}
			body, err := io.ReadAll(r.Body)
			if err != nil {
				http.Error(w, "failed to read body", http.StatusBadRequest)
				return
			}
			defer r.Body.Close()
			from, err1 := OutboundIndexByName(c.outbounds, params[0])
			to, err2 := OutboundIndexByName(c.outbounds, string(body))
			if err1 != nil || err2 != nil {
				http.Error(w, "outbound not found", http.StatusNotFound)
				return
			}
			c.muOutboundRedirects.Lock()
			if from == to {
				delete(c.outboundRedirects, from)
			} else {
				c.outboundRedirects[from] = to
			}
			c.muOutboundRedirects.Unlock()

			// Sync eBPF so redirect to direct/block happens in kernel space.
			if err := c.syncRedirectToEbpf(from, to); err != nil {
				log.Warnf("Failed to sync eBPF redirect for %v -> %v: %v", from, to, err)
			}
			fmt.Fprintf(writer, "OK\n")
		}
	case "priority":
		if r.Method == "GET" {
			if len(params) > 0 {
				http.Error(w, fmt.Sprintf("GET priority shouldn't have parameters: %v", params), http.StatusBadRequest)
				return
			}
			for _, dg := range c.outbounds {
				fmt.Fprintf(writer, "*** Outbound '%s':\n", dg.Name)
				for _, d := range dg.Dialers {
					anno := dg.GetAnnotation(d)
					fmt.Fprintf(writer, "-   [%s] %s: %d;%v\n", d.SubscriptionTag, d.Name, anno.Priority, anno.ConditionalPriority)
				}
			}
			return
		}
		if r.Method == "PUT" {
			outbound := ""
			subtag := ""
			dialerName := ""
			for _, param := range params {
				k, v, _ := strings.Cut(param, ":")
				switch k {
				case "outbound":
					outbound = v
				case "subtag":
					subtag = v
				case "dialer":
					dialerName = v
				}
			}
			for _, dg := range c.outbounds {
				if dg.Name == outbound {
					if len(dialerName) == 0 && len(subtag) == 0 {
						http.Error(w, "dialer name and subtag cannot be both empty", http.StatusBadRequest)
						return
					}
					body, err := io.ReadAll(r.Body)
					if err != nil {
						http.Error(w, "failed to read body", http.StatusBadRequest)
						return
					}
					defer r.Body.Close()
					pri, condPris, err := dialer.ParsePriority(string(body))
					if err != nil {
						http.Error(w, fmt.Sprintf("failed to parse priority string: %v", body), http.StatusBadRequest)
						return
					}
					var found bool
					for _, d := range dg.Dialers {
						if (len(dialerName) == 0 || strings.Contains(d.Name, dialerName)) && (len(subtag) == 0 || d.SubscriptionTag == subtag) {
							anno := dg.GetAnnotation(d)
							anno.Priority = pri
							anno.ConditionalPriority = condPris
							found = true
						}
					}
					if found {
						fmt.Fprintf(writer, "OK\n")
					} else {
						http.Error(w, fmt.Sprintf("Dialer '%s' with subtag '%s' not found in outbound '%s'", dialerName, subtag, outbound), http.StatusNotFound)
					}
					return
				}
			}
			fmt.Fprintf(writer, "Outbound '%s' not found\n", outbound)
		}
	case "lookup":
		if r.Method != http.MethodGet {
			http.Error(w, "GET method required", http.StatusMethodNotAllowed)
			return
		}
		if len(params) != 1 || params[0] == "" {
			http.Error(w, "lookup requires 1 IP parameter: /lookup/<ip>", http.StatusBadRequest)
			return
		}
		addr, err := netip.ParseAddr(params[0])
		if err != nil {
			http.Error(w, fmt.Sprintf("invalid IP %q: %v", params[0], err), http.StatusBadRequest)
			return
		}
		infos := c.dnsController.LookupDomainsByIP(addr)
		if len(infos) == 0 {
			http.Error(w, fmt.Sprintf("no domain found for IP %v", addr), http.StatusNotFound)
			return
		}
		for _, info := range infos {
			fmt.Fprintf(writer, "%s:\n", info.QName)
			fmt.Fprintf(writer, "  ttl: %v\n", info.TTL)
		}
	case "static":
		if len(params) == 0 {
			// GET /static - list all static entries
			if r.Method == "GET" {
				entries := c.dnsController.GetStaticEntries()
				for name, entry := range entries {
					fmt.Fprintf(writer, "%s:\n", name)
					if len(entry.A) > 0 {
						fmt.Fprintf(writer, "  a: %v\n", entry.A)
					}
					if len(entry.AAAA) > 0 {
						fmt.Fprintf(writer, "  aaaa: %v\n", entry.AAAA)
					}
					if len(entry.TXT) > 0 {
						fmt.Fprintf(writer, "  txt: %v\n", entry.TXT)
					}
					fmt.Fprintf(writer, "  ttl: %v\n", entry.TTL)
				}
				return
			}
			http.Error(w, "GET or DELETE method required", http.StatusMethodNotAllowed)
			return
		}
		staticName := params[0]
		switch r.Method {
		case "GET":
			// GET /static/{name} - get specific entry
			entry, ok := c.dnsController.GetStaticEntry(staticName)
			if !ok {
				http.Error(w, fmt.Sprintf("static entry %q not found", staticName), http.StatusNotFound)
				return
			}
			if len(entry.A) > 0 {
				fmt.Fprintf(writer, "a: %v\n", entry.A)
			}
			if len(entry.AAAA) > 0 {
				fmt.Fprintf(writer, "aaaa: %v\n", entry.AAAA)
			}
			if len(entry.TXT) > 0 {
				fmt.Fprintf(writer, "txt: %v\n", entry.TXT)
			}
			fmt.Fprintf(writer, "ttl: %v\n", entry.TTL)
			return
		case "PUT":
			// PUT /static/{name} - add/update entry
			body, err := io.ReadAll(r.Body)
			if err != nil {
				http.Error(w, "failed to read body", http.StatusBadRequest)
				return
			}
			defer r.Body.Close()
			// Parse body as config.DnsStaticEntry
			// Format: a: 1.2.3.4\naaaa: ::1\ntxt: hello
			entry, err := parseStaticEntry(string(body))
			if err != nil {
				http.Error(w, fmt.Sprintf("failed to parse static entry: %v", err), http.StatusBadRequest)
				return
			}
			if err := c.dnsController.UpdateStaticEntry(staticName, entry); err != nil {
				http.Error(w, fmt.Sprintf("failed to add static entry: %v", err), http.StatusInternalServerError)
				return
			}
			fmt.Fprintf(writer, "OK\n")
		default:
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}
	default:
		http.NotFound(w, r)
	}
}

// parseStaticEntry parses body content into config.DnsStaticEntry.
// Format: a: 1.2.3.4
//
//	aaaa: ::1
//	txt: hello
//	ttl: 60
func parseStaticEntry(body string) (*config.DnsStaticEntry, error) {
	entry := &config.DnsStaticEntry{}
	lines := strings.Split(body, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		key, value, _ := strings.Cut(line, ":")
		key = strings.TrimSpace(key)
		value = strings.TrimSpace(value)
		switch key {
		case "a":
			entry.A = append(entry.A, value)
		case "aaaa":
			entry.AAAA = append(entry.AAAA, value)
		case "txt":
			entry.TXT = append(entry.TXT, value)
		case "ttl":
			ttl, err := strconv.ParseUint(value, 10, 32)
			if err != nil {
				return nil, fmt.Errorf("invalid ttl: %v", err)
			}
			entry.TTL = uint32(ttl)
		}
	}
	return entry, nil
}

func ParseFixedDomainTtl(ks []config.KeyableString) (map[string]int, error) {
	m := make(map[string]int)
	for _, k := range ks {
		key, value, _ := strings.Cut(string(k), ":")
		key = common.CanonicalName(strings.TrimSpace(key))
		ttl, err := strconv.ParseInt(strings.TrimSpace(value), 0, strconv.IntSize)
		if err != nil {
			return nil, common.Errf("failed to parse ttl: %v", err)
		}
		m[key] = int(ttl)
	}
	return m, nil
}

func convertUdpSniffPorts(ports []string) []uint16 {
	result := make([]uint16, 0, len(ports))
	for _, p := range ports {
		if p == "" {
			continue
		}
		n, err := strconv.ParseUint(p, 10, 16)
		if err != nil {
			log.Warnf("invalid udp_sniff_ports value %q: %v", p, err)
			continue
		}
		result = append(result, uint16(n))
	}
	return result
}

func ParseGroupOverrideOption(group config.Group, global config.GlobalTrimmed) (*dialer.GlobalOption, error) {
	result := global
	changed := false
	// if group.TcpCheckUrl != nil {
	// 	result.TcpCheckUrl = group.TcpCheckUrl
	// 	changed = true
	// }
	// if group.TcpCheckHttpMethod != "" {
	// 	result.TcpCheckHttpMethod = group.TcpCheckHttpMethod
	// 	changed = true
	// }
	if group.UdpCheckDns != nil {
		result.UdpCheckDns = group.UdpCheckDns
		changed = true
	}
	if group.CheckInterval != 0 {
		result.CheckInterval = group.CheckInterval
		changed = true
	}
	if group.CheckTolerance != 0 {
		result.CheckTolerance = group.CheckTolerance
		changed = true
	}
	if changed {
		option := dialer.NewGlobalOption(&result)
		return option, nil
	}
	return nil, nil
}

// EjectBpf will resect bpf from destroying life-cycle of control plane.
func (c *ControlPlane) EjectBpf() *bpfObjects {
	return c.core.EjectBpf()
}
func (c *ControlPlane) InjectBpf(bpf *bpfObjects) {
	c.core.InjectBpf(bpf)
}

// SetConfigState stores config-derived state for subscription updates.
func (c *ControlPlane) SetConfigState(cfgFile, subscriptionDir string, conf *config.Config) {
	c.cfgFile = cfgFile
	c.subscriptionDir = subscriptionDir
	c.config = conf.Trim()
}

func (c *ControlPlane) cacheDnsUpstream(dnsUpstream *dns.Upstream) {
	/// Updates dns cache to support domain routing for hostname of dns_upstream.
	fqdn := common.CanonicalName(dnsUpstream.Hostname)
	var ips []netip.Addr

	if dnsUpstream.Ip4.IsValid() {
		ips = append(ips, dnsUpstream.Ip4)

	}

	if dnsUpstream.Ip6.IsValid() {
		ips = append(ips, dnsUpstream.Ip6)

	}
	c.dnsController.MaybeUpdateLookupCache(fqdn, ips, time.Hour*24*365*10) // Ten years later.
}

// verified 返回 domain 是不是 dst 的域名
// shouldReroute 返回 Kernel 是否有可能没有正确 Route
// SniffVerifyMode_Loose 在这个域名存在时, 通过认证
// SniffVerifyMode_Strict 在这个域名尝试过对应的 DNS 解析时, 通过认证
func (c *ControlPlane) VerifySniff(outbound consts.OutboundIndex, dst netip.AddrPort, domain string) (verified bool, shouldRerouteFunc func() bool) {
	if domain == "" {
		return
	}
	fqdn := common.CanonicalName(domain)
	qHash := c.dnsController.QnameHash(fqdn)
	var hasIpForDomain, isDstInIps bool
	c.dnsController.mu.Lock()
	if n, ok := c.dnsController.lookupCache[qHash]; ok && n > 0 {
		hasIpForDomain = true
		_, isDstInIps = c.dnsController.coreIpDomainCache.Get(QnameIpHash(qHash, dst.Addr()))
	}
	c.dnsController.mu.Unlock()

	if hasIpForDomain {
		// Successful sniff without DNS lookup record.
		// In this case, the kernel may not handle domain match set, so re-route is required.
		switch c.sniffVerifyMode {
		case consts.SniffVerifyMode_None, consts.SniffVerifyMode_Loose:
			verified = true
			shouldRerouteFunc = func() bool {
				return !isDstInIps
			}
		case consts.SniffVerifyMode_Strict:
			verified = isDstInIps
			shouldRerouteFunc = func() bool {
				return !isDstInIps
			}
		}
	} else {
		// Successful sniff without DNS lookup record.
		// Only tries to reroute when the domain is mentioned in routing rules.
		shouldRerouteFunc = func() bool {
			bitmap := common.ObtainDomainBitmap()
			defer common.RecycleDomainBitmap(bitmap)
			c.routingMatcher.domainMatcher.MatchDomainBitmapInplace(fqdn, bitmap)
			for _, v := range bitmap {
				if v != 0 {
					return true
				}
			}
			return false
		}
		// Check if the domain is in real-domain set (bloom filter).
		switch c.sniffVerifyMode {
		case consts.SniffVerifyMode_None:
			verified = true
		case consts.SniffVerifyMode_Strict:
			verified = false
		case consts.SniffVerifyMode_Loose:
			// TODO: 产生一个真的DNS查询? 这样能被缓存
			c.muRealDomainSet.Lock()
			verified = c.realDomainSet.TestString(fqdn) // Test if the domain is in real-domain set.
			c.muRealDomainSet.Unlock()
			if !verified {
				// Lookup A/AAAA to make sure it is a real domain.
				// TODO: 这里可能可以直接使用正常的 DNS 解析流程, 从而可以得到缓存
				if ip46, err := netutils.ResolveIp46(fqdn); err == nil && ip46.IsValid() {
					// Has A/AAAA records. It is a real domain.
					// Add it to real-domain set.
					c.muRealDomainSet.Lock()
					c.realDomainSet.AddString(fqdn)
					c.muRealDomainSet.Unlock()
					verified = true
				}
			}
		}
	}
	return
}

type Listener struct {
	tcpListener net.Listener
	packetConn  net.PacketConn
	port        uint16
}

func (l *Listener) Close() error {
	var (
		err  error
		err2 error
	)
	if err, err2 = l.tcpListener.Close(), l.packetConn.Close(); err2 != nil {
		if err == nil {
			err = err2
		} else {
			err = common.Errf("%w: %v", err, err2)
		}
	}
	return err
}

func (c *ControlPlane) Serve(readyChan chan<- bool, listener *Listener) (err error) {
	sentReady := false
	defer func() {
		if !sentReady {
			readyChan <- false
		}
	}()
	/// Serve.
	// TCP socket.
	tcpFile, err := listener.tcpListener.(*net.TCPListener).File()
	if err != nil {
		return common.Errf("failed to retrieve copy of the underlying TCP connection file")
	}
	c.deferFuncs = append(c.deferFuncs, func() error {
		return tcpFile.Close()
	})
	if err := c.core.bpf.ListenSocketMap.Update(consts.ZeroKey, uint64(tcpFile.Fd()), ebpf.UpdateAny); err != nil {
		return err
	}
	// UDP socket.
	udpConn := listener.packetConn.(*net.UDPConn)
	udpConn.SetDeadline(time.Time{})
	udpFile, err := udpConn.File()
	if err != nil {
		return common.Errf("failed to retrieve copy of the underlying UDP connection file")
	}
	c.deferFuncs = append(c.deferFuncs, func() error {
		udpConn.SetDeadline(time.Unix(0, 1)) // unblock ReadMsgUDPAddrPort
		return udpFile.Close()
	})
	if err := c.core.bpf.ListenSocketMap.Update(consts.OneKey, uint64(udpFile.Fd()), ebpf.UpdateAny); err != nil {
		return err
	}

	sentReady = true
	readyChan <- true
	// Reports memory usage every 10 seconds.
	tickerMem := time.NewTicker(10 * time.Second)
	go func() {
		defer tickerMem.Stop()
		for {
			select {
			case <-tickerMem.C:
				var ms runtime.MemStats
				runtime.ReadMemStats(&ms)
				common.Metrics.StackInuse.With0().Set(int64(ms.StackInuse) / 1024)
				common.Metrics.HeapInuse.With0().Set(int64(ms.HeapInuse) / 1024)
				common.Metrics.HeapIdle.With0().Set(int64(ms.HeapIdle) / 1024)
				common.Metrics.HeapReleased.With0().Set(int64(ms.HeapReleased) / 1024)
			case <-c.ctx.Done():
				return
			}
		}
	}()
	go c.loopTcp(listener)

	DefaultAnyfromPool = NewAnyfromPool()
	go DefaultAnyfromPool.Start(c.ctx)

	udpTaskChan := c.startUdpWorkers(100)
	go c.loopUdp(udpConn, udpTaskChan)

	c.bpfMapJanitor.Start(c.ctx)

	<-c.ctx.Done()
	return nil
}

func (c *ControlPlane) loopTcp(listener *Listener) {
	for {
		select {
		case <-c.ctx.Done():
			return
		default:
		}
		lconn, err := listener.tcpListener.Accept()
		if err != nil {
			if !strings.Contains(err.Error(), "use of closed network connection") {
				log.Errorf("%+v", common.Wrap(err, "Error when accept"))
			}
			break
		}
		go func(lconn net.Conn) {
			c.inConnections.Store(lconn, struct{}{})
			defer c.inConnections.Delete(lconn)
			if err := c.handleConn(lconn); err != nil && c.ctx.Err() == nil {
				if log.IsLevelEnabled(log.ErrorLevel) {
					log.Errorf("%+v", common.Wrap(err, "handleConn"))
				}
			}
		}(lconn)
	}
}

type udpRoutineParam struct {
	buf    []byte
	oobBuf []byte
	src    netip.AddrPort
}

var udpRoutineParamPool = sync.Pool{
	New: func() any { return &udpRoutineParam{} },
}

func obtainUdpRoutineParam(udpConn *net.UDPConn) (*udpRoutineParam, error) {
	param := udpRoutineParamPool.Get().(*udpRoutineParam)
	param.buf = pool.GetBuffer(consts.EthernetMtu)
	param.oobBuf = pool.GetBuffer(128)
	n, oobn, _, src, err := udpConn.ReadMsgUDPAddrPort(param.buf, param.oobBuf)
	if err != nil {
		pool.PutBuffer(param.buf)
		pool.PutBuffer(param.oobBuf)
		udpRoutineParamPool.Put(param)
		return nil, err
	}
	param.src = src
	param.buf = param.buf[:n]
	param.oobBuf = param.oobBuf[:oobn]
	return param, nil
}

func recycleUdpRoutineParam(param *udpRoutineParam) {
	param.buf = nil
	param.oobBuf = nil
	udpRoutineParamPool.Put(param)
}

func (c *ControlPlane) loopUdp(udpConn *net.UDPConn, udpTaskChan chan *udpRoutineParam) {
	for {
		select {
		case <-c.ctx.Done():
			return
		default:
		}
		param, err := obtainUdpRoutineParam(udpConn)
		if err != nil {
			if !strings.Contains(err.Error(), "use of closed network connection") {
				if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
					log.Errorf("ReadMsgUDPAddrPort failed: %v", err)
				}
			}
			break
		}
		select {
		case udpTaskChan <- param:
		case <-c.ctx.Done():
			pool.PutBuffer(param.buf)
			pool.PutBuffer(param.oobBuf)
			recycleUdpRoutineParam(param)
		}
	}
}

func (c *ControlPlane) startUdpWorkers(workerCount int) chan *udpRoutineParam {
	udpTaskChan := make(chan *udpRoutineParam, 10240)
	for i := 0; i < workerCount; i++ {
		go func() {
			for {
				select {
				case <-c.ctx.Done():
					return
				case p, ok := <-udpTaskChan:
					if !ok {
						return
					}
					c.udpRoutine(p)
				}
			}
		}()
	}
	return udpTaskChan
}

func (c *ControlPlane) udpRoutine(param *udpRoutineParam) {
	defer recycleUdpRoutineParam(param)
	dst := RetrieveOriginalDest(param.oobBuf)
	if !dst.IsValid() {
		log.Errorf("Invalid dst from oob: %v, cap: %d", param.oobBuf, cap(param.oobBuf))
		pool.PutBuffer(param.oobBuf)
		pool.PutBuffer(param.buf)
		return
	}
	pool.PutBuffer(param.oobBuf)
	dst = common.ConvergeAddrPort(dst)
	src := common.ConvergeAddrPort(param.src)
	data := param.buf
	/// Handle DNS
	// To keep consistency with kernel program, we only sniff DNS request sent to 53.
	if dst.Port() == 53 {
		var routingResult *bpfRoutingResult
		var ok bool
		if routingResult, ok = c.dnsRoutingResultCache.Get(src.Addr()); !ok {
			var err error
			// Don't use ObtainBpfRoutingResult() because it would be saved in cache.
			routingResult = new(bpfRoutingResult)
			// DNS routing is per-IP, not per-sport.
			dnsSrc := netip.AddrPortFrom(src.Addr(), 0)
			if err = c.core.RetrieveUDPRoutingResult(dnsSrc, dst, routingResult); err != nil {
				if log.IsLevelEnabled(log.ErrorLevel) {
					log.Errorf("%+v", common.Wrap(err, "Failed to retrieve udp 53 routing result, src: %v", src))
				}
				pool.PutBuffer(data)
				return
			}
			c.dnsRoutingResultCache.Save(src.Addr(), routingResult)
		}
		if routingResult.Must == 0 {
			dq := ObtainDnsRequest(src, dst, routingResult, false)
			handled := c.dnsController.Handle(data, dq)
			if handled {
				RecycleDnsRequest(dq)
				pool.PutBuffer(data)
				return
			}
			RecycleDnsRequest(dq)
		}
	}

	emitTask := obtainUdpEmitTask(src, dst, data, c)
	if !c.udpTaskPool.EmitTask(src, emitTask) {
		recycleUdpEmitTask(emitTask)
	}
}

type emitParam struct {
	AddrPortPair
	data []byte
	c    *ControlPlane
}

var udpEmitTaskPool = sync.Pool{
	New: func() any { return &UdpTask[emitParam]{} },
}

func udpEmitTaskFunc(t *UdpTask[emitParam]) {
	p := &t.param
	defer recycleUdpEmitTask(t)
	if e := p.c.handlePkt(p.data, p.Src, p.Dst); e != nil && p.c.ctx.Err() == nil {
		if log.IsLevelEnabled(log.ErrorLevel) {
			log.Errorf("%+v", common.Wrap(e, "handlePkt"))
		}
	}
}

func obtainUdpEmitTask(src, dst netip.AddrPort, data []byte, c *ControlPlane) *UdpTask[emitParam] {
	t := udpEmitTaskPool.Get().(*UdpTask[emitParam])
	t.param.Src = src
	t.param.Dst = dst
	t.param.data = data
	t.param.c = c
	t.exec = udpEmitTaskFunc
	return t
}

func recycleUdpEmitTask(t *UdpTask[emitParam]) {
	pool.PutBuffer(t.param.data)
	t.param.data = nil
	t.exec = nil
	udpEmitTaskPool.Put(t)
}

func (c *ControlPlane) ListenAndServe(readyChan chan<- bool, port uint16) (listener *Listener, err error) {
	// Listen.
	var listenConfig = net.ListenConfig{
		Control: func(network, address string, c syscall.RawConn) error {
			return dialer.TproxyControl(c)
		},
	}
	listenAddr := net.JoinHostPort(c.listenIp, strconv.Itoa(int(port)))
	tcpListener, err := listenConfig.Listen(context.TODO(), "tcp", listenAddr)
	if err != nil {
		return nil, common.Errf("listenTCP: %w", err)
	}
	packetConn, err := listenConfig.ListenPacket(context.TODO(), "udp", listenAddr)
	if err != nil {
		_ = tcpListener.Close()
		return nil, common.Errf("listenUDP: %w", err)
	}
	listener = &Listener{
		tcpListener: tcpListener,
		packetConn:  packetConn,
		port:        port,
	}
	defer func() {
		if err != nil {
			_ = listener.Close()
		}
	}()

	// Serve
	if err = c.Serve(readyChan, listener); err != nil {
		return nil, common.Errf("failed to serve: %w", err)
	}

	return listener, nil
}

func (c *ControlPlane) chooseBestDnsDialer(
	req *dnsRequest,
	dnsUpstream *dns.Upstream,
	outArg *dialArgument,
) error {
	if dnsUpstream.Scheme == dns.UpstreamScheme_Static {
		// Makes dummy dial argument to avoid panic (e.g. when priting logs).
		outArg.networkType = common.IndexToNetworkType(0)
		outArg.Outbound = c.outbounds[0]
		outArg.Dialer = c.outbounds[0].Dialers[0]
		return nil
	}
	/// Choose the best l4proto+ipversion dialer, and change taregt DNS to the best ipversion DNS upstream for DNS request.
	// Get available ipversions and l4protos for DNS upstream.
	var (
		l4proto      consts.L4ProtoStr
		ipversion    consts.IpVersionStr
		bestDialer   *dialer.Dialer
		bestOutbound *outbound.DialerGroup
		bestTarget   netip.AddrPort
		// dialMark     uint32
	)
	var routeKey dnsRouteCacheKey
	if !dnsUpstream.IsAsIs {
		// AsIs's upstream instance is dynamic, so it doesn't support route cache.
		routeKey.upstream = dnsUpstream
		routeKey.src = req.Src.Addr()
	}
	// Get the min latency path.
	var networkType *common.NetworkType
	for i := 3; i >= 0; i-- {
		networkType = common.IndexToNetworkType(i)
		if !dnsUpstream.IsNetworkSupported(networkType) {
			continue
		}
		var dAddr netip.Addr
		ver := networkType.IpVersion
		proto := networkType.L4Proto
		switch ver {
		case consts.IpVersionStr_4:
			dAddr = dnsUpstream.Ip4
		case consts.IpVersionStr_6:
			dAddr = dnsUpstream.Ip6
		default:
			return common.Errf("unexpected ipversion: %v", ver)
		}
		outboundIndex := dnsUpstream.Outbound
		if outboundIndex < consts.OutboundUserDefinedMin || outboundIndex > consts.OutboundUserDefinedMax {
			var ok bool
			if routeKey.upstream != nil {
				outboundIndex, ok = c.dnsRouteCache.Get(routeKey)
			}
			if !ok {
				var err error
				// TODO: Mark
				outboundIndex, _, _, err = c.Route(req.Src, netip.AddrPortFrom(dAddr, dnsUpstream.Port), dnsUpstream.Hostname, proto.ToL4ProtoType(), req.routingResult)
				if err != nil {
					return err
				}
				if int(outboundIndex) >= len(c.outbounds) {
					return common.Errf("bad outbound index: %v", outboundIndex)
				}
				if routeKey.upstream != nil {
					c.dnsRouteCache.Save(routeKey, outboundIndex)
				}
			}
		}
		// Handles outbound redirects
		c.muOutboundRedirects.RLock()
		redirected, exists := c.outboundRedirects[outboundIndex]
		c.muOutboundRedirects.RUnlock()
		if exists {
			outboundIndex = redirected
		}
		dialerGroup := c.outbounds[outboundIndex]
		// DNS always dial IP.
		d, err := dialerGroup.Select(networkType)
		if err != nil {
			continue
		}
		bestDialer = d
		bestOutbound = dialerGroup
		l4proto = proto
		ipversion = ver
		// dialMark = mark
		break
	}

	if bestDialer == nil {
		return common.Errf("no proper dialer for DNS upstream: %v", dnsUpstream.String())
	}
	switch ipversion {
	case consts.IpVersionStr_4:
		bestTarget = netip.AddrPortFrom(dnsUpstream.Ip4, dnsUpstream.Port)
	case consts.IpVersionStr_6:
		bestTarget = netip.AddrPortFrom(dnsUpstream.Ip6, dnsUpstream.Port)
	}
	if log.IsLevelEnabled(log.TraceLevel) {
		log.WithFields(log.Fields{
			"upstream": dnsUpstream.String(),
			"choose":   string(l4proto) + "+" + string(ipversion),
			"use":      bestTarget.String(),
			"outbound": bestOutbound.Name,
			"dialer":   bestDialer.Name,
		}).Traceln("Choose DNS path")
	}
	outArg.networkType = networkType
	outArg.Dialer = bestDialer
	outArg.Outbound = bestOutbound
	outArg.Target = bestTarget
	// outArg.mark = dialMark
	return nil
}

// UpdateSubscriptions re-fetches subscriptions and hot-swaps dialers
// in existing DialerGroups without rebuilding routing or BPF state.
func (c *ControlPlane) UpdateSubscriptions() error {
	c.muUpdateSub.Lock()
	defer c.muUpdateSub.Unlock()

	if c.config == nil {
		return fmt.Errorf("control plane not initialized for subscription updates")
	}

	log.Warnln("[update-sub] Starting subscription update...")

	// Phase 0: Re-read group/node/subscription definitions from config file.
	// Allows filter/policy/annotation edits without full reload.
	newGroups, newNodes, newSubs, err := c.reparseDynamicSections()
	if err != nil {
		return fmt.Errorf("re-reading config failed (use SIGUSR1 for full reload): %w", err)
	}
	if err := validateGroupStructure(c.config.Group, newGroups); err != nil {
		return fmt.Errorf("group structure changed, use SIGUSR1 for full reload: %w", err)
	}
	c.config.Group = newGroups
	c.config.Node = newNodes
	c.config.Sub = newSubs

	if err := c.rebuildOutboundRedirects(newGroups); err != nil {
		return fmt.Errorf("redirect update failed: %w", err)
	}

	// Phase 1: Re-resolve subscriptions.
	client := http.Client{
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				return direct.Direct.DialContext(ctx, "tcp", addr)
			},
		},
		Timeout: 30 * time.Second,
	}
	nodeStrs := make([]string, len(c.config.Node))
	for i, n := range c.config.Node {
		nodeStrs[i] = string(n)
	}
	subStrs := make([]string, len(c.config.Sub))
	for i, s := range c.config.Sub {
		subStrs[i] = string(s)
	}
	newTagToNodeList := subscription.ResolveAllSubscriptions(&client, c.subscriptionDir, nodeStrs, subStrs)
	if len(newTagToNodeList) == 0 {
		return fmt.Errorf("no nodes resolved from any subscription")
	}

	// Phase 2: Build new DialerSet from fresh data.
	option := dialer.NewGlobalOption(c.config.Global)
	newDialerSet := outbound.NewDialerSetFromLinks(option, newTagToNodeList)

	// Phase 3: For each user-defined outbound group, re-filter and swap dialers.

	groupCfgIdx := 0
	for i := int(consts.OutboundUserDefinedMin); i < len(c.outbounds); i++ {
		group := c.outbounds[i]

		if groupCfgIdx >= len(c.config.Group) {
			log.Warnf("[update-sub] Group index %d exceeds config groups; skipping %s", groupCfgIdx, group.Name)
			groupCfgIdx++
			continue
		}
		groupCfg := c.config.Group[groupCfgIdx]
		groupCfgIdx++

		// Skip redirect groups — they don't have subscription nodes.
		if len(groupCfg.Redirect) > 0 && groupCfg.Name != groupCfg.Redirect {
			continue
		}

		// Re-filter nodes using the stored group config against fresh nodes.
		newDialers, newAnnos, err := newDialerSet.FilterAndAnnotate(
			groupCfg.Filter, groupCfg.FilterAnnotation, groupCfg.NextHop)
		if err != nil {
			return fmt.Errorf("group %q: %w", group.Name, err)
		}

		// Apply group-level option override if any.
		var groupOpt *dialer.GlobalOption
		if groupCfg.UdpCheckDns != nil || groupCfg.CheckInterval != 0 || groupCfg.CheckTolerance != 0 {
			groupOpt, err = ParseGroupOverrideOption(groupCfg, *c.config.Global)
			if err != nil {
				return fmt.Errorf("group %q: %w", group.Name, err)
			}
		}
		if groupOpt != nil {
			for j, d := range newDialers {
				cloned := d.Clone()
				cloned.GlobalOption = groupOpt
				newDialers[j] = cloned
			}
		}

		// Log updated node list.
		log.Infof("[update-sub] Group %q updated node list:", group.Name)
		for _, d := range newDialers {
			log.Infoln("\t" + d.Name)
		}
		if len(newDialers) == 0 {
			log.Infoln("\t<Empty>")
		}

		// Hot-swap dialers in the group.
		group.ReplaceDialers(newDialers, newAnnos)
	}

	// Phase 4: Cleanup.
	// Build current in-use set from all group dialers.
	newInuse := make(map[*dialer.Dialer]bool)
	for _, g := range c.outbounds {
		for _, d := range g.Dialers {
			newInuse[d] = true
		}
	}
	// Close orphaned old dialers (in c.inuseDialers but not in any group).
	for _, d := range c.inuseDialers {
		if !newInuse[d] {
			d.Close()
		}
	}

	// Clear connectivity check metrics — orphaned stale entries from removed dialers.
	// Fresh metrics will be set by the ReactivateCheck goroutines.
	common.Metrics.CheckLatency.Reset()
	common.Metrics.CheckMovingLatency.Reset()
	common.Metrics.CheckSelectLatency.Reset()
	common.Metrics.DialerSelectIndex.Reset()

	// Update the in-use dialer list and activate checks.
	c.inuseDialers = make([]*dialer.Dialer, 0, len(newInuse))
	for d := range newInuse {
		c.inuseDialers = append(c.inuseDialers, d)
		d.ReactivateCheck()
	}

	runtime.GC()
	log.Warnln("[update-sub] Subscription update completed successfully")
	return nil
}

// reparseDynamicSections re-reads the config file and extracts group, node,
// and subscription sections — the parts that change between subscription updates.
func (c *ControlPlane) reparseDynamicSections() (groups []config.Group, nodes, subs []config.KeyableString, err error) {
	data, err := os.ReadFile(c.cfgFile)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to read config file: %w", err)
	}
	sections, err := config_parser.Parse(string(data))
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to parse config file: %w", err)
	}
	for _, sec := range sections {
		switch sec.Name {
		case "group":
			if err := config.SectionParser(reflect.ValueOf(&groups), sec); err != nil {
				return nil, nil, nil, fmt.Errorf("failed to parse group section: %w", err)
			}
		case "node":
			if err := config.SectionParser(reflect.ValueOf(&nodes), sec); err != nil {
				return nil, nil, nil, fmt.Errorf("failed to parse node section: %w", err)
			}
		case "subscription":
			if err := config.SectionParser(reflect.ValueOf(&subs), sec); err != nil {
				return nil, nil, nil, fmt.Errorf("failed to parse subscription section: %w", err)
			}
		}
	}
	if groups == nil {
		return nil, nil, nil, fmt.Errorf("group section not found in config")
	}
	return groups, nodes, subs, nil
}

// validateGroupStructure ensures the new group layout is compatible with
// the existing outbounds. Name and count must match.
func validateGroupStructure(oldGroups, newGroups []config.Group) error {
	if len(newGroups) != len(oldGroups) {
		return fmt.Errorf("group count changed (%d -> %d)", len(oldGroups), len(newGroups))
	}
	for i := range newGroups {
		old := &oldGroups[i]
		new_ := &newGroups[i]
		if old.Name != new_.Name {
			return fmt.Errorf("group name changed at index %d (%q -> %q)", i, old.Name, new_.Name)
		}
		oldIsRedirect := old.Redirect != ""
		newIsRedirect := new_.Redirect != ""
		if oldIsRedirect != newIsRedirect {
			return fmt.Errorf("group %q redirect nature changed; use SIGUSR1 for full reload", old.Name)
		}
	}
	return nil
}

// rebuildOutboundRedirects rebuilds the redirect lookup map from config groups.
func (c *ControlPlane) rebuildOutboundRedirects(groups []config.Group) error {
	redirects := make(map[consts.OutboundIndex]consts.OutboundIndex)
	for _, g := range groups {
		if g.Redirect == "" || g.Name == g.Redirect {
			continue
		}
		fromIdx, err := OutboundIndexByName(c.outbounds, g.Name)
		if err != nil {
			return fmt.Errorf("redirect source %q: %w", g.Name, err)
		}
		toIdx, err := OutboundIndexByName(c.outbounds, g.Redirect)
		if err != nil {
			return fmt.Errorf("redirect target %q: %w", g.Redirect, err)
		}
		redirects[fromIdx] = toIdx
	}
	c.muOutboundRedirects.Lock()
	c.outboundRedirects = redirects
	c.muOutboundRedirects.Unlock()

	// Sync eBPF outbound_connectivity_map for kernel-space short-circuit.
	for fromIdx, toIdx := range redirects {
		if err := c.syncRedirectToEbpf(fromIdx, toIdx); err != nil {
			return err
		}
	}
	return nil
}

// syncRedirectToEbpf updates the eBPF outbound_connectivity_map so the kernel
// program can short-circuit traffic for fromIdx. When toIdx is OutboundDirect
// or OutboundBlock, all (l4proto × ipversion) combinations are set to force
// direct/block in kernel space. Otherwise value 0 is written, restoring normal
// userspace handling.
func (c *ControlPlane) syncRedirectToEbpf(fromIdx, toIdx consts.OutboundIndex) error {
	if fromIdx == consts.OutboundDirect || fromIdx == consts.OutboundBlock {
		return fmt.Errorf("cannot redirect from reserved outbound index %d", fromIdx)
	}
	// 0: go control plane
	// 1: direct
	// 2: block
	value := uint32(0)
	if toIdx == consts.OutboundDirect || toIdx == consts.OutboundBlock {
		value = uint32(toIdx) + 1
	}
	for i := range 4 {
		networkType := common.IndexToNetworkType(i)
		key := bpfOutboundConnectivityQuery{
			Outbound:  uint8(fromIdx),
			L4proto:   networkType.L4Proto.ToL4Proto(),
			Ipversion: networkType.IpVersion.ToIpVersion(),
		}
		if err := c.core.bpf.OutboundConnectivityMap.Update(key, value, ebpf.UpdateAny); err != nil {
			return fmt.Errorf("outbound %v l4=%v ipv=%v: %w", fromIdx, networkType.L4Proto, networkType.IpVersion, err)
		}
	}
	return nil
}

// buildOutboundName2Id reconstructs the outbound name→index mapping from
// the ControlPlane's outbound groups. Used during hot routing updates.
func (c *ControlPlane) buildOutboundName2Id() map[string]uint8 {
	m := make(map[string]uint8, len(c.outbounds))
	for i, g := range c.outbounds {
		m[g.Name] = uint8(i)
	}
	return m
}

// reparseRoutingSection re-reads and merges the config file, then
// extracts the routing section. It uses the merger (which resolves
// includes) so that external rule files are properly handled.
func (c *ControlPlane) reparseRoutingSection() (*config.Routing, error) {
	merger := config.NewMerger(c.cfgFile)
	sections, _, err := merger.Merge()
	if err != nil {
		return nil, fmt.Errorf("failed to merge config: %w", err)
	}
	for _, sec := range sections {
		if sec.Name == "routing" {
			var routingCfg config.Routing
			if err := config.SectionParser(reflect.ValueOf(&routingCfg), sec); err != nil {
				return nil, fmt.Errorf("failed to parse routing section: %w", err)
			}
			return &routingCfg, nil
		}
	}
	return nil, fmt.Errorf("routing section not found in config")
}

// UpdateRouting re-reads the routing section from the config file and
// applies new rules in-place without closing dialers or disrupting
// established connections. It mirrors UpdateSubscriptions in spirit:
// only the routing layer is swapped; BPF objects, dialers, and DNS
// state are preserved.
func (c *ControlPlane) UpdateRouting() error {
	c.muUpdateRouting.Lock()
	defer c.muUpdateRouting.Unlock()

	log.Warnln("[update-routing] Starting routing update...")

	// Phase 0: Re-read routing section from config file.
	routingCfg, err := c.reparseRoutingSection()
	if err != nil {
		return fmt.Errorf("re-reading routing config failed: %w", err)
	}

	// Phase 1: Apply rules optimizers (same pipeline as full reload).
	rules, err := routing.ApplyRulesOptimizers(routingCfg.Rules,
		&routing.AliasOptimizer{},
		&routing.DatReaderOptimizer{LocationFinder: c.locationFinder},
		&routing.MergeAndSortRulesOptimizer{},
		&routing.DeduplicateParamsOptimizer{},
	)
	if err != nil {
		return fmt.Errorf("ApplyRulesOptimizers: %w", err)
	}

	// Phase 2: Build userspace matcher (no kernel side effects).
	outboundName2Id := c.buildOutboundName2Id()
	builder, err := NewRoutingMatcherBuilder(rules, outboundName2Id, c.core.bpf, routingCfg.Fallback, c.core.ifmgr)
	if err != nil {
		return fmt.Errorf("NewRoutingMatcherBuilder: %w", err)
	}
	newRoutingMatcher, err := builder.BuildUserspace()
	if err != nil {
		return fmt.Errorf("BuildUserspace: %w", err)
	}

	// Phase 3: Build kernel space — overwrites RoutingMap + LpmArrayMap
	// + RoutingMetaMap in-place inside the shared BPF object. Existing
	// routing_tuples_map entries are untouched so established flows
	// continue with their cached decisions.
	if err = builder.BuildKernspace(); err != nil {
		return fmt.Errorf("BuildKernspace: %w", err)
	}

	// Phase 4: Atomic swap of userspace routing matcher.
	c.routingMatcher = newRoutingMatcher

	// Phase 5: Replay DNS domain bitmaps through the new matcher.
	// The MatchBitmap callback reads c.routingMatcher dynamically, so
	// after the swap above it already uses the new domain matcher.
	if c.dnsController != nil {
		c.dnsController.ReplayDomainBitmaps(func(fqdn string, bitmap []uint32) {
			c.routingMatcher.domainMatcher.MatchDomainBitmapInplace(fqdn, bitmap)
		})
	}

	// Phase 6: Clear routing-dependent ephemeral caches.
	c.dnsRouteCache = common.NewTimeWheelCache[dnsRouteCacheKey, consts.OutboundIndex](1*time.Hour, 5*time.Second, nil)

	runtime.GC()
	log.Warnln("[update-routing] Routing update completed successfully")
	return nil
}

func (c *ControlPlane) AbortConnections() (err error) {
	var errs []error
	c.inConnections.Range(func(key, value any) bool {
		if err = key.(net.Conn).Close(); err != nil {
			errs = append(errs, err)
		}
		return true
	})
	return errors.Join(errs...)
}

func (c *ControlPlane) Close() (err error) {
	c.dnsRouteCache.Close()
	c.dnsRoutingResultCache.Close()

	// Stop janitor before cancel (so BPF maps are still valid during cleanup).
	c.bpfMapJanitor.Stop()

	// Invoke defer funcs in reverse order.
	for i := len(c.deferFuncs) - 1; i >= 0; i-- {
		if e := c.deferFuncs[i](); e != nil {
			// Combine errors.
			if err != nil {
				err = common.Errf("%w; %v", err, e)
			} else {
				err = e
			}
		}
	}
	for _, d := range c.inuseDialers {
		if e := d.Close(); e != nil {
			if err != nil {
				err = common.Errf("%w; %v", err, e)
			} else {
				err = e
			}
		}
	}
	c.cancel()
	if e := c.core.Close(); e != nil {
		if err != nil {
			err = common.Errf("%w; %v", err, e)
		} else {
			err = e
		}
	}
	return
}
