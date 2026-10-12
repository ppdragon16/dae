package control

import (
	"testing"

	"github.com/daeuniverse/dae/common/consts"
)

// TestNeedsBlockingSniff pins the gate that decides whether the relay waits
// for the sniff: only the cases where the domain can still change the outcome
// block; a connection the kernel already routed to a concrete outbound starts
// relaying immediately.
func TestNeedsBlockingSniff(t *testing.T) {
	node := consts.OutboundIndex(7)
	cases := []struct {
		name               string
		outbound           consts.OutboundIndex
		rerouteMode        consts.RerouteMode
		dialTargetOverride bool
		want               bool
	}{
		{"control plane routing", consts.OutboundControlPlaneRouting, consts.RerouteMode_WhileNeed, false, true},
		{"force reroute", node, consts.RerouteMode_Force, false, true},
		{"dial target override", node, consts.RerouteMode_WhileNeed, true, true},
		{"kernel-routed node", node, consts.RerouteMode_WhileNeed, false, false},
		{"kernel-routed direct", consts.OutboundDirect, consts.RerouteMode_WhileNeed, false, false},
		{"force wins over everything", consts.OutboundDirect, consts.RerouteMode_Force, true, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := needsBlockingSniff(tc.outbound, tc.rerouteMode, tc.dialTargetOverride); got != tc.want {
				t.Fatalf("needsBlockingSniff(%v, %v, %v) = %v, want %v", tc.outbound, tc.rerouteMode, tc.dialTargetOverride, got, tc.want)
			}
		})
	}
}
