/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2026, daeuniverse Organization <dae@v2raya.org>
 */

package routing

import (
	"strings"
	"testing"

	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/pkg/config_parser"
)

// TestOperandParsersRejectUnknownValues pins the operand contract: an unknown
// value such as l4proto(sctp) used to be silently ignored, so the rule compiled
// into a never-matching no-op while every validator accepted the config; an
// argument list that yields no bit at all (l4proto()) was accepted as well.
// A rejected value must be a loud error naming the function, and an empty
// selection must be rejected. (Port of kdae 60b970f3.)
func TestOperandParsersRejectUnknownValues(t *testing.T) {
	f := func(name string) *config_parser.Function { return &config_parser.Function{Name: name} }
	l4proto := L4ProtoParserFactory(func(f *config_parser.Function, t consts.L4ProtoType, oo *Outbound) error {
		return nil
	})
	ipversion := IpVersionParserFactory(func(f *config_parser.Function, t consts.IpVersionType, oo *Outbound) error {
		return nil
	})

	for _, c := range []struct {
		name     string
		run      func() error
		wantErr  string
		wantType consts.L4ProtoType
		wantVer  consts.IpVersionType
	}{
		{"l4proto(tcp)", func() error { return l4proto(f("l4proto"), "", []string{"tcp"}, nil) }, "", consts.L4ProtoType_TCP, 0},
		{"l4proto(udp)", func() error { return l4proto(f("l4proto"), "", []string{"udp"}, nil) }, "", consts.L4ProtoType_UDP, 0},
		{"l4proto(utp)", func() error { return l4proto(f("l4proto"), "", []string{"utp"}, nil) }, "", consts.L4ProtoType_uTP, 0},
		{"l4proto(tcp,udp)", func() error { return l4proto(f("l4proto"), "", []string{"tcp", "udp"}, nil) }, "", consts.L4ProtoType_TCP | consts.L4ProtoType_UDP, 0},
		{"l4proto(sctp)", func() error { return l4proto(f("l4proto"), "", []string{"sctp"}, nil) }, "unknown value", 0, 0},
		{"l4proto(tcp,sctp)", func() error { return l4proto(f("l4proto"), "", []string{"tcp", "sctp"}, nil) }, "unknown value", 0, 0},
		{"l4proto()", func() error { return l4proto(f("l4proto"), "", nil, nil) }, "at least one", 0, 0},
		{"ipversion(4)", func() error { return ipversion(f("ipversion"), "", []string{"4"}, nil) }, "", 0, consts.IpVersion_4},
		{"ipversion(4,6)", func() error { return ipversion(f("ipversion"), "", []string{"4", "6"}, nil) }, "", 0, consts.IpVersion_4 | consts.IpVersion_6},
		{"ipversion(5)", func() error { return ipversion(f("ipversion"), "", []string{"5"}, nil) }, "unknown value", 0, 0},
		{"ipversion()", func() error { return ipversion(f("ipversion"), "", nil, nil) }, "at least one", 0, 0},
	} {
		err := c.run()
		if c.wantErr != "" {
			if err == nil {
				t.Fatalf("%v: unknown operand silently accepted", c.name)
			}
			if !strings.Contains(err.Error(), c.wantErr) || !strings.Contains(err.Error(), strings.SplitN(c.name, "(", 2)[0]) {
				t.Fatalf("%v: error should name the function and %q, got %v", c.name, c.wantErr, err)
			}
			continue
		}
		if err != nil {
			t.Fatalf("%v: must stay accepted, got %v", c.name, err)
		}
	}
}
