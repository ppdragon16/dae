/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"context"
	"errors"
	"net/netip"
	"os"
	"regexp"
	"sync"

	"github.com/cilium/ebpf"
	ciliumLink "github.com/cilium/ebpf/link"
	"github.com/daeuniverse/dae/common"
	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/component"
	internal "github.com/daeuniverse/dae/pkg/ebpf_internal"
	"github.com/mohae/deepcopy"
	"github.com/safchain/ethtool"
	log "github.com/sirupsen/logrus"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

// coreFlip should be 0 or 1
var coreFlip = 0
var exitHandlerClose func() error

type controlPlaneCore struct {
	mu sync.Mutex

	deferFuncs []func() error
	bpf        *bpfState

	kernelVersion *internal.Version

	flip       int
	isReload   bool
	bpfEjected bool

	// IP -> per-rule match state. Single source of truth for both
	// domain_bump_map and domain_routing_map in eBPF; pushed verbatim
	// to the kernel on every change so the two states stay in sync.
	domainStates  map[netip.Addr]*domainState
	domainStateMu sync.Mutex

	// domainBitLength is the number of rule-index slots a domainState.matched
	// slice needs (max domain rule index + 1). Set from the routing matcher
	// once it is built; sized lazily per domainState so a small config does
	// not waste ~4KB per IP.
	domainBitLength int

	closed context.Context
	close  context.CancelFunc
	ifmgr  *component.InterfaceManager
}

func newControlPlaneCore(
	bpf *bpfState,
	kernelVersion *internal.Version,
	isReload bool,
) *controlPlaneCore {
	if isReload {
		coreFlip = coreFlip&1 ^ 1
	}
	var deferFuncs []func() error
	if !isReload {
		deferFuncs = append(deferFuncs, bpf.Close)
	}
	closed, toClose := context.WithCancel(context.Background())
	ifmgr := component.NewInterfaceManager()
	deferFuncs = append(deferFuncs, ifmgr.Close)
	core := &controlPlaneCore{
		deferFuncs:    deferFuncs,
		bpf:           bpf,
		kernelVersion: kernelVersion,
		flip:          coreFlip,
		isReload:      isReload,
		bpfEjected:    false,
		ifmgr:         ifmgr,
		domainStates:  make(map[netip.Addr]*domainState),
		closed:        closed,
		close:         toClose,
	}

	// Hot-update dae0 ifindex via dae_ifindex_map when the kernel recreates
	// the device and assigns a new ifindex. Previously this required a full
	// dae restart (SIGUSR1 reload reuses bpfObjects and does NOT refresh
	// PARAM.dae0_ifindex).
	ifmgr.Register(HostVethName,
		func(link netlink.Link) {
			// initCallback: set initial ifindex in the runtime map.
			bpf := core.bpf
			if bpf == nil || bpf.DaeIfindexMap == nil {
				return
			}
			if err := bpf.DaeIfindexMap.Update(uint32(0), uint32(link.Attrs().Index), ebpf.UpdateAny); err != nil {
				log.Errorf("Failed to init dae_ifindex_map: %v", err)
			}
		},
		func(link netlink.Link) {
			// newCallback: dae0 was recreated; hot-update if it drifted.
			newIfindex := uint32(link.Attrs().Index)
			bpf := core.bpf
			if bpf == nil || bpf.DaeIfindexMap == nil {
				return
			}
			var currentIfindex uint32
			if err := bpf.DaeIfindexMap.Lookup(uint32(0), &currentIfindex); err != nil {
				currentIfindex = 0
			}
			if newIfindex == currentIfindex {
				return
			}
			if err := bpf.DaeIfindexMap.Update(uint32(0), newIfindex, ebpf.UpdateAny); err != nil {
				log.Errorf("Failed to update dae_ifindex_map: %v", err)
			} else {
				log.Warnf("dae0 ifindex drift detected and recovered: %d -> %d", currentIfindex, newIfindex)
			}
		},
		nil,
	)

	return core
}

func (c *controlPlaneCore) Flip() {
	coreFlip = coreFlip&1 ^ 1
}
func (c *controlPlaneCore) Close() (err error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	select {
	case <-c.closed.Done():
		return nil
	default:
	}
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
	c.close()
	return err
}

func getIfParamsFromLink(link netlink.Link) (ifParams bpfIfParams, err error) {
	// Get link offload features.
	et, err := ethtool.NewEthtool()
	if err != nil {
		return bpfIfParams{}, err
	}
	defer et.Close()
	features, err := et.Features(link.Attrs().Name)
	if err != nil {
		return bpfIfParams{}, err
	}
	if features["tx-checksum-ip-generic"] {
		ifParams.TxL4CksmIp4Offload = true
		ifParams.TxL4CksmIp6Offload = true
	}
	if features["tx-checksum-ipv4"] {
		ifParams.TxL4CksmIp4Offload = true
	}
	if features["tx-checksum-ipv6"] {
		ifParams.TxL4CksmIp6Offload = true
	}
	if features["rx-checksum"] {
		ifParams.RxCksmOffload = true
	}
	switch {
	case regexp.MustCompile(`^docker\d+$`).MatchString(link.Attrs().Name):
		ifParams.UseNonstandardOffloadAlgorithm = true
	default:
	}
	return ifParams, nil
}

func (c *controlPlaneCore) linkHdrLen(ifname string) (uint32, error) {
	link, err := netlink.LinkByName(ifname)
	if err != nil {
		return 0, err
	}
	var linkHdrLen uint32
	switch link.Attrs().EncapType {
	case "none", "ipip", "ppp", "tun":
		linkHdrLen = consts.LinkHdrLen_None
	case "ether":
		linkHdrLen = consts.LinkHdrLen_Ethernet
	default:
		log.Warnf("Maybe unsupported link type %v, using default link header length", link.Attrs().EncapType)
		linkHdrLen = consts.LinkHdrLen_Ethernet
	}
	return linkHdrLen, nil
}

func (c *controlPlaneCore) addQdisc(ifname string) error {
	link, err := netlink.LinkByName(ifname)
	if err != nil {
		return err
	}
	qdisc := &netlink.GenericQdisc{
		QdiscAttrs: netlink.QdiscAttrs{
			LinkIndex: link.Attrs().Index,
			Handle:    netlink.MakeHandle(0xffff, 0),
			Parent:    netlink.HANDLE_CLSACT,
		},
		QdiscType: "clsact",
	}
	if err := netlink.QdiscReplace(qdisc); err != nil {
		return common.Errf("cannot replace clsact qdisc: %w", err)
	}
	return nil
}

func (c *controlPlaneCore) delQdisc(ifname string) error {
	link, err := netlink.LinkByName(ifname)
	if err != nil {
		return err
	}
	qdisc := &netlink.GenericQdisc{
		QdiscAttrs: netlink.QdiscAttrs{
			LinkIndex: link.Attrs().Index,
			Handle:    netlink.MakeHandle(0xffff, 0),
			Parent:    netlink.HANDLE_CLSACT,
		},
		QdiscType: "clsact",
	}
	if err := netlink.QdiscDel(qdisc); err != nil {
		if !os.IsExist(err) {
			return common.Errf("cannot add clsact qdisc: %w", err)
		}
	}
	return nil
}

// bindLan automatically configures kernel parameters and bind to lan interface `ifname`.
// bindLan supports lazy-bind if interface `ifname` is not found.
// bindLan supports rebinding when the interface `ifname` is detected in the future.
func (c *controlPlaneCore) bindLan(ifname string, autoConfigKernelParameter bool) {
	initlinkCallback := func(link netlink.Link) {
		if link.Attrs().Name == HostVethName {
			return
		}
		if autoConfigKernelParameter {
			SetSendRedirects(link.Attrs().Name, "0")
			SetForwarding(link.Attrs().Name, "1")
		}
		if err := c._bindLan(link.Attrs().Name); err != nil {
			log.Errorf("bindLan: %v", err)
		}
	}
	newlinkCallback := func(link netlink.Link) {
		if link.Attrs().Name == HostVethName {
			return
		}
		log.Warnf("New link creation of '%v' is detected. Bind LAN program to it.", link.Attrs().Name)
		if err := c.addQdisc(link.Attrs().Name); err != nil {
			log.Errorf("addQdisc: %v", err)
			return
		}
		initlinkCallback(link)
	}
	dellinkCallback := func(link netlink.Link) {
		if link.Attrs().Name == HostVethName {
			return
		}
		log.Warnf("Link deletion of '%v' is detected. Bind LAN program to it once it is re-created.", link.Attrs().Name)
	}
	c.ifmgr.RegisterWithPattern(ifname, initlinkCallback, newlinkCallback, dellinkCallback)
}

func (c *controlPlaneCore) _bindLan(ifname string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	select {
	case <-c.closed.Done():
		return nil
	default:
	}
	log.Infof("Bind to LAN: %v", ifname)

	link, err := netlink.LinkByName(ifname)
	if err != nil {
		return err
	}
	if err = CheckIpforward(ifname); err != nil {
		return err
	}
	if err = CheckSendRedirects(ifname); err != nil {
		return err
	}
	_ = c.addQdisc(ifname)
	linkHdrLen, err := c.linkHdrLen(ifname)
	if err != nil {
		return err
	}
	/// Insert an elem into IfindexParamsMap.
	ifParams, err := getIfParamsFromLink(link)
	if err != nil {
		return err
	}
	if err = ifParams.CheckVersionRequirement(c.kernelVersion); err != nil {
		return err
	}

	// Insert filters.
	filterIngress := &netlink.BpfFilter{
		FilterAttrs: netlink.FilterAttrs{
			LinkIndex: link.Attrs().Index,
			Parent:    netlink.HANDLE_MIN_INGRESS,
			Handle:    netlink.MakeHandle(0x2023, 0b100+uint16(c.flip)),
			Protocol:  unix.ETH_P_ALL,
			// Priority should be behind of WAN's
			Priority: 2,
		},
		Name:         consts.AppName + "_lan_ingress",
		DirectAction: true,
	}
	if linkHdrLen > 0 {
		filterIngress.Fd = c.bpf.bpfPrograms.LanIngressL2.FD()
		filterIngress.Name = filterIngress.Name + "_l2"
	} else {
		filterIngress.Fd = c.bpf.bpfPrograms.LanIngressL3.FD()
		filterIngress.Name = filterIngress.Name + "_l3"
	}
	// Remove and add.
	_ = netlink.FilterDel(filterIngress)
	if !c.isReload {
		// Clean up thoroughly.
		filterIngressFlipped := deepcopy.Copy(filterIngress).(*netlink.BpfFilter)
		filterIngressFlipped.FilterAttrs.Handle ^= 1
		_ = netlink.FilterDel(filterIngressFlipped)
	}
	if err := netlink.FilterAdd(filterIngress); err != nil {
		return common.Errf("cannot attach ebpf object to filter ingress: %w", err)
	}
	c.deferFuncs = append(c.deferFuncs, func() error {
		if err := netlink.FilterDel(filterIngress); err != nil {
			return common.Errf("FilterDel(%v:%v): %w", ifname, filterIngress.Name, err)
		}
		return nil
	})

	filterEgress := &netlink.BpfFilter{
		FilterAttrs: netlink.FilterAttrs{
			LinkIndex: link.Attrs().Index,
			Parent:    netlink.HANDLE_MIN_EGRESS,
			Handle:    netlink.MakeHandle(0x2023, 0b010+uint16(c.flip)),
			Protocol:  unix.ETH_P_ALL,
			// Priority should be front of WAN's
			Priority: 1,
		},
		Name:         consts.AppName + "_lan_egress",
		DirectAction: true,
	}
	if linkHdrLen > 0 {
		filterEgress.Fd = c.bpf.bpfPrograms.LanEgressL2.FD()
		filterEgress.Name = filterEgress.Name + "_l2"
	} else {
		filterEgress.Fd = c.bpf.bpfPrograms.LanEgressL3.FD()
		filterEgress.Name = filterEgress.Name + "_l3"
	}
	// Remove and add.
	_ = netlink.FilterDel(filterEgress)
	if !c.isReload {
		// Clean up thoroughly.
		filterEgressFlipped := deepcopy.Copy(filterEgress).(*netlink.BpfFilter)
		filterEgressFlipped.FilterAttrs.Handle ^= 1
		_ = netlink.FilterDel(filterEgressFlipped)
	}
	if err := netlink.FilterAdd(filterEgress); err != nil {
		return common.Errf("cannot attach ebpf object to filter egress: %w", err)
	}
	c.deferFuncs = append(c.deferFuncs, func() error {
		if err := netlink.FilterDel(filterEgress); err != nil {
			return common.Errf("FilterDel(%v:%v): %w", ifname, filterEgress.Name, err)
		}
		return nil
	})

	return nil
}

func (c *controlPlaneCore) setupSkPidMonitor() error {
	/// Set-up SrcPidMapper.
	/// Attach programs to support pname routing.
	// Get the first-mounted cgroupv2 path.
	cgroupPath, err := detectCgroupPath()
	if err != nil {
		return err
	}
	// Bind cg programs
	type cgProg struct {
		Name   string
		Prog   *ebpf.Program
		Attach ebpf.AttachType
	}
	cgProgs := []cgProg{
		{Prog: c.bpf.TproxyWanCgSockCreate, Attach: ebpf.AttachCGroupInetSockCreate},
		{Prog: c.bpf.TproxyWanCgSockRelease, Attach: ebpf.AttachCgroupInetSockRelease},
		{Prog: c.bpf.TproxyWanCgConnect4, Attach: ebpf.AttachCGroupInet4Connect},
		{Prog: c.bpf.TproxyWanCgConnect6, Attach: ebpf.AttachCGroupInet6Connect},
		{Prog: c.bpf.TproxyWanCgSendmsg4, Attach: ebpf.AttachCGroupUDP4Sendmsg},
		{Prog: c.bpf.TproxyWanCgSendmsg6, Attach: ebpf.AttachCGroupUDP6Sendmsg},
	}
	for _, prog := range cgProgs {
		attached, err := ciliumLink.AttachCgroup(ciliumLink.CgroupOptions{
			Path:    cgroupPath,
			Attach:  prog.Attach,
			Program: prog.Prog,
		})
		if err != nil {
			return common.Wrap(err, "AttachCgroup: %v", prog.Prog.String())
		}
		c.deferFuncs = append(c.deferFuncs, func() error {
			return common.Wrap(attached.Close(), "inet6Bind.Close()")
		})
	}
	return nil
}

func (c *controlPlaneCore) setupExitHandler() (err error) {
	if exitHandlerClose != nil {
		exitHandlerClose()
	}
	link, err := ciliumLink.Tracepoint("sched", "sched_process_exit", c.bpf.HandleExit, nil)
	if err != nil {
		return common.Errf("Tracepoint: %w", err)
	}
	exitHandlerClose = link.Close
	return nil
}

// bindWan supports lazy-bind if interface `ifname` is not found.
// bindWan supports rebinding when the interface `ifname` is detected in the future.
func (c *controlPlaneCore) bindWan(ifname string, autoConfigKernelParameter bool) {
	initlinkCallback := func(link netlink.Link) {
		if link.Attrs().Name == HostVethName {
			return
		}
		if err := c._bindWan(link.Attrs().Name); err != nil {
			log.Errorf("bindWan: %v", err)
		}
	}
	newlinkCallback := func(link netlink.Link) {
		if link.Attrs().Name == HostVethName {
			return
		}
		log.Warnf("New link creation of '%v' is detected. Bind WAN program to it.", link.Attrs().Name)
		if err := c.addQdisc(link.Attrs().Name); err != nil {
			log.Errorf("addQdisc: %v", err)
			return
		}
		initlinkCallback(link)
	}
	dellinkCallback := func(link netlink.Link) {
		if link.Attrs().Name == HostVethName {
			return
		}
		log.Warnf("Link deletion of '%v' is detected. Bind WAN program to it once it is re-created.", link.Attrs().Name)
	}
	c.ifmgr.RegisterWithPattern(ifname, initlinkCallback, newlinkCallback, dellinkCallback)
}

func (c *controlPlaneCore) _bindWan(ifname string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	select {
	case <-c.closed.Done():
		return nil
	default:
	}
	log.Infof("Bind to WAN: %v", ifname)
	link, err := netlink.LinkByName(ifname)
	if err != nil {
		return err
	}
	if link.Attrs().Index == consts.LoopbackIfIndex {
		return common.Errf("cannot bind to loopback interface")
	}
	_ = c.addQdisc(ifname)
	linkHdrLen, err := c.linkHdrLen(ifname)
	if err != nil {
		return err
	}

	/// Insert an elem into IfindexParamsMap.
	ifParams, err := getIfParamsFromLink(link)
	if err != nil {
		return err
	}
	if err = ifParams.CheckVersionRequirement(c.kernelVersion); err != nil {
		return err
	}

	/// Set-up WAN ingress/egress TC programs.
	// Insert TC filters
	filterEgress := &netlink.BpfFilter{
		FilterAttrs: netlink.FilterAttrs{
			LinkIndex: link.Attrs().Index,
			Parent:    netlink.HANDLE_MIN_EGRESS,
			Handle:    netlink.MakeHandle(0x2023, 0b100+uint16(c.flip)),
			Protocol:  unix.ETH_P_ALL,
			Priority:  2,
		},
		Name:         consts.AppName + "_wan_egress",
		DirectAction: true,
	}
	if linkHdrLen > 0 {
		filterEgress.Fd = c.bpf.bpfPrograms.TproxyWanEgressL2.FD()
		filterEgress.Name = filterEgress.Name + "_l2"
	} else {
		filterEgress.Fd = c.bpf.bpfPrograms.TproxyWanEgressL3.FD()
		filterEgress.Name = filterEgress.Name + "_l3"
	}
	_ = netlink.FilterDel(filterEgress)
	// Remove and add.
	if !c.isReload {
		// Clean up thoroughly.
		filterEgressFlipped := deepcopy.Copy(filterEgress).(*netlink.BpfFilter)
		filterEgressFlipped.FilterAttrs.Handle ^= 1
		_ = netlink.FilterDel(filterEgressFlipped)
	}
	if err := netlink.FilterAdd(filterEgress); err != nil {
		return common.Errf("cannot attach ebpf object to filter egress: %w", err)
	}
	c.deferFuncs = append(c.deferFuncs, func() error {
		if err := netlink.FilterDel(filterEgress); err != nil && !os.IsNotExist(err) {
			return common.Errf("FilterDel(%v:%v): %w", ifname, filterEgress.Name, err)
		}
		return nil
	})

	filterIngress := &netlink.BpfFilter{
		FilterAttrs: netlink.FilterAttrs{
			LinkIndex: link.Attrs().Index,
			Parent:    netlink.HANDLE_MIN_INGRESS,
			Handle:    netlink.MakeHandle(0x2023, 0b010+uint16(c.flip)),
			Protocol:  unix.ETH_P_ALL,
			Priority:  1,
		},
		Name:         consts.AppName + "_wan_ingress",
		DirectAction: true,
	}
	if linkHdrLen > 0 {
		filterIngress.Fd = c.bpf.bpfPrograms.TproxyWanIngressL2.FD()
		filterIngress.Name = filterIngress.Name + "_l2"
	} else {
		filterIngress.Fd = c.bpf.bpfPrograms.TproxyWanIngressL3.FD()
		filterIngress.Name = filterIngress.Name + "_l3"
	}
	_ = netlink.FilterDel(filterIngress)
	// Remove and add.
	if !c.isReload {
		// Clean up thoroughly.
		filterIngressFlipped := deepcopy.Copy(filterIngress).(*netlink.BpfFilter)
		filterIngressFlipped.FilterAttrs.Handle ^= 1
		_ = netlink.FilterDel(filterIngressFlipped)
	}
	if err := netlink.FilterAdd(filterIngress); err != nil {
		return common.Errf("cannot attach ebpf object to filter ingress: %w", err)
	}
	c.deferFuncs = append(c.deferFuncs, func() error {
		if err := netlink.FilterDel(filterIngress); err != nil && !os.IsNotExist(err) {
			return common.Errf("FilterDel(%v:%v): %w", ifname, filterIngress.Name, err)
		}
		return nil
	})

	return nil
}

func (c *controlPlaneCore) bindDaens() (err error) {
	daens := GetDaeNetns()

	// tproxy_dae0peer_ingress@eth0 at dae netns
	daens.With(func() error {
		err := netlink.LinkSetTxQLen(daens.Dae0Peer(), 1000)
		if err == nil {
			err = c.addQdisc(daens.Dae0Peer().Attrs().Name)
		}
		return err
	})
	filterDae0peerIngress := &netlink.BpfFilter{
		FilterAttrs: netlink.FilterAttrs{
			LinkIndex: daens.Dae0Peer().Attrs().Index,
			Parent:    netlink.HANDLE_MIN_INGRESS,
			Handle:    netlink.MakeHandle(0x2022, 0b010+uint16(c.flip)),
			Protocol:  unix.ETH_P_ALL,
			Priority:  0,
		},
		Fd:           c.bpf.bpfPrograms.TproxyDae0peerIngress.FD(),
		Name:         consts.AppName + "_dae0peer_ingress",
		DirectAction: true,
	}
	daens.With(func() error {
		return netlink.FilterDel(filterDae0peerIngress)
	})
	// Remove and add.
	if !c.isReload {
		// Clean up thoroughly.
		filterIngressFlipped := deepcopy.Copy(filterDae0peerIngress).(*netlink.BpfFilter)
		filterIngressFlipped.FilterAttrs.Handle ^= 1
		daens.With(func() error {
			return netlink.FilterDel(filterDae0peerIngress)
		})
	}
	if err = daens.With(func() error {
		return netlink.FilterAdd(filterDae0peerIngress)
	}); err != nil {
		return common.Errf("cannot attach ebpf object to filter ingress: %w", err)
	}
	c.deferFuncs = append(c.deferFuncs, func() error {
		daens.With(func() error {
			return netlink.FilterDel(filterDae0peerIngress)
		})
		return nil
	})

	// tproxy_dae0_ingress@dae0 at host netns
	c.addQdisc(daens.Dae0().Attrs().Name)
	filterDae0Ingress := &netlink.BpfFilter{
		FilterAttrs: netlink.FilterAttrs{
			LinkIndex: daens.Dae0().Attrs().Index,
			Parent:    netlink.HANDLE_MIN_INGRESS,
			Handle:    netlink.MakeHandle(0x2022, 0b010+uint16(c.flip)),
			Protocol:  unix.ETH_P_ALL,
			Priority:  0,
		},
		Fd:           c.bpf.bpfPrograms.TproxyDae0Ingress.FD(),
		Name:         consts.AppName + "_dae0_ingress",
		DirectAction: true,
	}
	_ = netlink.FilterDel(filterDae0Ingress)
	// Remove and add.
	if !c.isReload {
		// Clean up thoroughly.
		filterEgressFlipped := deepcopy.Copy(filterDae0Ingress).(*netlink.BpfFilter)
		filterEgressFlipped.FilterAttrs.Handle ^= 1
		_ = netlink.FilterDel(filterEgressFlipped)
	}
	if err := netlink.FilterAdd(filterDae0Ingress); err != nil {
		return common.Errf("cannot attach ebpf object to filter egress: %w", err)
	}
	c.deferFuncs = append(c.deferFuncs, func() error {
		if err := netlink.FilterDel(filterDae0Ingress); err != nil && !os.IsNotExist(err) {
			return common.Errf("FilterDel(%v:%v): %w", daens.Dae0().Attrs().Name, filterDae0Ingress.Name, err)
		}
		return nil
	})
	return
}

func getBit(bitmap []uint32, index int) uint32 {
	return bitmap[index/32] >> (index % 32) & 1
}

func setBit(bitmap []uint32, index int) {
	bitmap[index/32] |= 1 << (index % 32)
}

// domainState tracks the per-rule match counts for a single IP. It is the
// sole source of truth for the two eBPF maps (domain_bump_map and
// domain_routing_map): every mutation recomputes both bitmaps from this
// struct and pushes them to the kernel, so user space and BPF stay in sync.
type domainState struct {
	// matched[i] = number of currently cached domains for this IP whose
	// match bitmap has rule i set. Sized to the highest domain rule index
	// (+1) actually used by the config; see controlPlaneCore.domainBitLength.
	matched []uint32
	// total = number of currently cached domains for this IP.
	total uint32
}

// add applies a domain's match bitmap to the per-IP state. An all-zero bitmap
// still increments total (it does not touch matched), which is what keeps the
// domain_routing_map invariant (matched[i] == total) correct.
func (s *domainState) add(bitmap *[32]uint32) {
	s.total++
	for i := range s.matched {
		s.matched[i] += getBit(bitmap[:], i)
	}
}

// remove undoes add for the same bitmap.
func (s *domainState) remove(bitmap *[32]uint32) {
	s.total--
	for i := range s.matched {
		s.matched[i] -= getBit(bitmap[:], i)
	}
}

// computeDomainBitmaps derives the two eBPF bitmaps from the per-IP domain
// state s.
//
// Invariants exposed to BPF:
//
//	domain_bump_map[ip]    bit i = (matched[i] > 0)            // any cached
//	                                                           // domain matches
//	domain_routing_map[ip] bit i = (matched[i] == total)       // all cached
//	                                                           // domains match
//
// matched[i] counts the cached domains for this IP whose match bitmap has rule
// i set; total counts ALL cached domains for this IP (including those whose
// bitmap is entirely zero). The routing bit therefore requires every cached
// domain to match rule i — a single non-matching domain clears it.
func computeDomainBitmaps(s *domainState) (bump, routing bpfDomainRouting) {
	if consts.MaxMatchSetLen/32 != len(bump.Bitmap) {
		panic("domain bitmap length not sync with kern program")
	}
	for i := range s.matched {
		if s.matched[i] == 0 {
			continue
		}
		setBit(bump.Bitmap[:], i)
		if s.matched[i] == s.total {
			setBit(routing.Bitmap[:], i)
		}
	}
	return bump, routing
}

// flushDomainState pushes the bitmaps derived from s to the eBPF maps for ip.
func (c *controlPlaneCore) flushDomainState(ip netip.Addr, s *domainState) error {
	bump, routing := computeDomainBitmaps(s)

	ip6 := ip.As16()
	key := common.Ipv6ByteSliceToUint32Array(ip6[:])
	if err := c.bpf.DomainBumpMap.Update(key, bump, ebpf.UpdateAny); err != nil {
		return err
	}
	return c.bpf.DomainRoutingMap.Update(key, routing, ebpf.UpdateAny)
}

// deleteDomainState removes ip from both eBPF maps.
func (c *controlPlaneCore) deleteDomainState(ip netip.Addr) error {
	ip6 := ip.As16()
	key := common.Ipv6ByteSliceToUint32Array(ip6[:])
	if err := c.bpf.DomainBumpMap.Delete(key); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
		return err
	}
	if err := c.bpf.DomainRoutingMap.Delete(key); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
		return err
	}
	return nil
}

// ClearDomainStates removes every (ip, bitmap) entry from the eBPF maps and
// drops the domainState structs. Used to rebuild the domain state from
// scratch (e.g. on routing reload).
func (c *controlPlaneCore) ClearDomainStates() error {
	c.domainStateMu.Lock()
	defer c.domainStateMu.Unlock()
	for ip := range c.domainStates {
		if err := c.deleteDomainState(ip); err != nil {
			return err
		}
	}
	c.domainStates = make(map[netip.Addr]*domainState)
	return nil
}

// BatchNewDomain registers a new (ip, domain) mapping discovered via DNS.
// domainBitmap describes which routing rules the domain matches.
func (c *controlPlaneCore) BatchNewDomain(ip netip.Addr, domainBitmap *[32]uint32) error {
	c.domainStateMu.Lock()
	defer c.domainStateMu.Unlock()

	s, ok := c.domainStates[ip]
	if !ok {
		s = c.newDomainState()
		c.domainStates[ip] = s
	}
	s.add(domainBitmap)
	return c.flushDomainState(ip, s)
}

// newDomainState allocates a domainState with its matched slice sized to the
// current domainBitLength. domainState entries live as long as the IP stays
// cached (min_sniffing_ttl), so no pooling is needed.
func (c *controlPlaneCore) newDomainState() *domainState {
	n := c.domainBitLength
	if n < 1 {
		n = 1
	}
	return &domainState{matched: make([]uint32, n)}
}

// BatchRemoveDomain unregisters a previously registered (ip, domain) mapping.
// domainBitmap MUST be the same bitmap passed to BatchNewDomain for this
// (ip, domain) pair. When the last cached domain for ip is removed, ip is
// also evicted from the eBPF maps.
func (c *controlPlaneCore) BatchRemoveDomain(ip netip.Addr, domainBitmap *[32]uint32) error {
	c.domainStateMu.Lock()
	defer c.domainStateMu.Unlock()

	s, ok := c.domainStates[ip]
	if !ok {
		return nil
	}
	s.remove(domainBitmap)
	if s.total == 0 {
		delete(c.domainStates, ip)
		return c.deleteDomainState(ip)
	}
	return c.flushDomainState(ip, s)
}

// EjectBpf will resect bpf from destroying life-cycle of control plane core.
func (c *controlPlaneCore) EjectBpf() *bpfState {
	if !c.bpfEjected && !c.isReload {
		c.deferFuncs = c.deferFuncs[1:]
	}
	c.bpfEjected = true
	return c.bpf
}

// InjectBpf will inject bpf back.
func (c *controlPlaneCore) InjectBpf(bpf *bpfState) {
	if c.bpfEjected {
		c.bpfEjected = false
		c.deferFuncs = append([]func() error{bpf.Close}, c.deferFuncs...)
	}
}
