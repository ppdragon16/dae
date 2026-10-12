package control

import (
	"github.com/daeuniverse/dae/common/consts"
)

// needsBlockingSniff reports whether the sniffed domain can still change the
// routing outcome, which is the only reason to block the relay on it:
//
//   - ControlPlaneRouting: the kernel punted this connection because the
//     domain is ambiguous (domain_bump hit without a definite routing match);
//     only the ClientHello's SNI can pick the outbound.
//   - RerouteMode_Force: every connection is re-routed in user space with the
//     sniffed domain.
//   - dialTargetOverride: the sniffed domain may replace the dial target.
//
// Everything else relays immediately on the kernel's verdict and classifies in
// the background for the log only.
func needsBlockingSniff(outbound consts.OutboundIndex, rerouteMode consts.RerouteMode, dialTargetOverride bool) bool {
	return outbound == consts.OutboundControlPlaneRouting ||
		rerouteMode == consts.RerouteMode_Force ||
		dialTargetOverride
}
