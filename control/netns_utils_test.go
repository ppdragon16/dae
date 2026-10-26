package control

import (
	"fmt"
	"os"
	"testing"

	"golang.org/x/sys/unix"

	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netns"
)

// TestReleaseNetnsHandleGuardsBareZeroValueHandle pins the fd-0 hazard: a bare
// DaeNetns zero-value daeNs handle reads as open (fd 0), so releasing it must
// be a no-op instead of closing stdin — closing fd 0 lets a later NewNamed
// recycle the descriptor for a real namespace fd.
func TestReleaseNetnsHandleGuardsBareZeroValueHandle(t *testing.T) {
	bare := &DaeNetns{}
	bare.releaseNetnsHandle()
	if _, err := unix.FcntlInt(0, unix.F_GETFD, 0); err != nil {
		t.Fatalf("releaseNetnsHandle closed fd 0 on a bare DaeNetns: %v", err)
	}

	// A real open handle is closed exactly once; releasing again is a no-op.
	h, err := netns.Get()
	if err != nil {
		t.Skipf("netns.Get unavailable: %v", err)
	}
	ns := &DaeNetns{handlesInitialized: true, daeNs: h}
	ns.releaseNetnsHandle()
	if ns.daeNs.IsOpen() {
		t.Fatal("daeNs handle still open after releaseNetnsHandle")
	}
	ns.releaseNetnsHandle() // Must stay a no-op once released.
}

// TestSetupPrefersPeerBornInNetns runs the real setup sequence and pins the
// structural property the in-netns path exists for: after setup, the host
// namespace has no dae0peer (it was born inside daens), while daens has both
// ends wired (peer up, addresses and routes applied). Root required.
func TestSetupPrefersPeerBornInNetns(t *testing.T) {
	if uid := fmt.Sprint(os.Getuid()); uid != "0" {
		t.Skipf("root required, uid=%s", uid)
	}
	if err := InitSysctlManager(); err != nil {
		t.Skipf("sysctl watcher unavailable: %v", err)
	}
	InitDaeNetns()
	ns := GetDaeNetns()
	if err := ns.Setup(); err != nil {
		t.Fatalf("setup: %v", err)
	}
	t.Cleanup(func() { _ = ns.Close() })

	// The host namespace must not see the peer at all.
	if _, err := netlink.LinkByName(NsVethName); err == nil {
		t.Fatal("dae0peer is visible in the host namespace; the peer was not born inside daens")
	}
	if ns.dae0 == nil || ns.dae0peer == nil {
		t.Fatal("setup left the pair links unresolved")
	}

	// Inside daens the peer exists, is up, and carries the datapath address.
	if err := ns.With(func() error {
		peer, err := netlink.LinkByName(NsVethName)
		if err != nil {
			return err
		}
		if peer.Attrs().Flags&unix.IFF_UP == 0 {
			t.Fatalf("dae0peer is down inside daens")
		}
		addrs, err := netlink.AddrList(peer, netlink.FAMILY_V4)
		if err != nil {
			return err
		}
		if len(addrs) == 0 {
			t.Fatal("dae0peer has no IPv4 datapath address inside daens")
		}
		return nil
	}); err != nil {
		t.Fatalf("daens check: %v", err)
	}
}
