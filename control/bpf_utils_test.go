package control

import "testing"

// TestBpfConstantsCarryDaeSocketMark pins that the configured
// global.so_mark_from_dae reaches the eBPF program's PARAM.dae_socket_mark.
//
// pid_is_control_plane() (control/kern/tproxy.c) uses that field to recognise
// dae's own sockets on the WAN egress hook; when it is zero the mark check is
// skipped entirely, so dae's own outbound packets (e.g. a tunnel's UDP packets)
// can be routed back into the proxy and the tunnel ends up feeding itself.
// Wiring the value into the loader is easy to lose again, hence this test.
func TestBpfConstantsCarryDaeSocketMark(t *testing.T) {
	for _, mark := range []uint32{1234, 0x80000000, 1} {
		constants, ok := bpfConstants(bpfDaeParamEnv{}, mark)["PARAM"].(daeParamConstant)
		if !ok {
			t.Fatalf("PARAM constant has unexpected type %T", bpfConstants(bpfDaeParamEnv{}, mark)["PARAM"])
		}
		if constants.daeSocketMark != mark {
			t.Fatalf("dae_socket_mark = %d, want %d: so_mark_from_dae never reaches the eBPF program", constants.daeSocketMark, mark)
		}
	}

	// An unset mark must stay unset: pid_is_control_plane() only consults the
	// mark when it is non-zero.
	constants := bpfConstants(bpfDaeParamEnv{}, 0)["PARAM"].(daeParamConstant)
	if constants.daeSocketMark != 0 {
		t.Fatalf("dae_socket_mark = %d, want 0 when so_mark_from_dae is unset", constants.daeSocketMark)
	}
}

// TestBpfConstantsCarryTheEnv guards the rest of the PARAM rewrite: the loader
// reads the netns, interfaces and kernel features, and those values must land in
// the constant (a wrong field mapping here would silently break tproxy).
func TestBpfConstantsCarryTheEnv(t *testing.T) {
	env := bpfDaeParamEnv{
		TproxyPort:           12345,
		ControlPlanePid:      678,
		Dae0Ifindex:          9,
		Dae0NetnsId:          42,
		Dae0PeerMac:          [6]byte{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff},
		UseRedirectPeer:      1,
		HasBpfGetCurrentTask: 1,
		TproxyReuseport:      1,
	}
	constants := bpfConstants(env, 1234)["PARAM"].(daeParamConstant)
	if constants.tproxyPort != env.TproxyPort ||
		constants.controlPlanePid != env.ControlPlanePid ||
		constants.dae0Ifindex != env.Dae0Ifindex ||
		constants.dae0NetnsId != env.Dae0NetnsId ||
		constants.dae0peerMac != env.Dae0PeerMac ||
		constants.useRedirectPeer != env.UseRedirectPeer ||
		constants.hasBpfGetCurrentTask != env.HasBpfGetCurrentTask ||
		constants.tproxyReuseport != env.TproxyReuseport {
		t.Fatalf("PARAM env mismatch: got %+v, want %+v", constants, env)
	}
	if constants.paddingAfterMac != [2]byte{} || constants.padding2 != 0 {
		t.Fatalf("padding must stay zero: %+v", constants)
	}
}
