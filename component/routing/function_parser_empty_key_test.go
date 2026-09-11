/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2026, daeuniverse Organization <dae@v2raya.org>
 */

package routing

import (
	"net/netip"
	"strings"
	"testing"

	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/pkg/config_parser"
)

// TestValueOnlyParsersRejectNamedParams pins the empty-key contract: the
// value-only factories used to ignore the parameter key entirely, so
// `port(bogus_param: 443)` silently built the same match set as `port(443)`.
// The bare form stays accepted; a named parameter is a loud error that names
// the function and the rejected key. (Port of kdae bdba15d3.)
func TestValueOnlyParsersRejectNamedParams(t *testing.T) {
	rejected := func(name string, err error) {
		t.Helper()
		if err == nil {
			t.Fatalf("%v: named parameter silently accepted", name)
		}
		if !strings.Contains(err.Error(), `unsupported parameter key "bogus_param"`) || !strings.Contains(err.Error(), name) {
			t.Fatalf("%v: error should name the function and the rejected key, got %v", name, err)
		}
	}
	accepted := func(name string, err error) {
		t.Helper()
		if err != nil {
			t.Fatalf("%v: bare form must stay accepted, got %v", name, err)
		}
	}

	f := func(name string) *config_parser.Function { return &config_parser.Function{Name: name} }

	port := PortRangeParserFactory(func(f *config_parser.Function, pr [][2]uint16, oo *Outbound) error { return nil })
	accepted("port", port(f("port"), "", []string{"443"}, nil))
	rejected("port", port(f("port"), "bogus_param", []string{"443"}, nil))

	l4proto := L4ProtoParserFactory(func(f *config_parser.Function, t consts.L4ProtoType, oo *Outbound) error { return nil })
	accepted("l4proto", l4proto(f("l4proto"), "", []string{"tcp"}, nil))
	rejected("l4proto", l4proto(f("l4proto"), "bogus_param", []string{"tcp"}, nil))

	ipversion := IpVersionParserFactory(func(f *config_parser.Function, t consts.IpVersionType, oo *Outbound) error { return nil })
	accepted("ipversion", ipversion(f("ipversion"), "", []string{"4"}, nil))
	rejected("ipversion", ipversion(f("ipversion"), "bogus_param", []string{"4"}, nil))

	pname := ProcessNameParserFactory(func(f *config_parser.Function, names [][consts.TaskCommLen]byte, oo *Outbound) error { return nil })
	accepted("pname", pname(f("pname"), "", []string{"curl"}, nil))
	rejected("pname", pname(f("pname"), "bogus_param", []string{"curl"}, nil))

	ip := IpParserFactory(func(f *config_parser.Function, cidrs []netip.Prefix, oo *Outbound) error { return nil })
	accepted("ip", ip(f("ip"), "", []string{"1.2.3.4"}, nil))
	rejected("ip", ip(f("ip"), "bogus_param", []string{"1.2.3.4"}, nil))

	mac := MacParserFactory(func(f *config_parser.Function, macs [][6]byte, oo *Outbound) error { return nil })
	accepted("mac", mac(f("mac"), "", []string{"aa:bb:cc:dd:ee:ff"}, nil))
	rejected("mac", mac(f("mac"), "bogus_param", []string{"aa:bb:cc:dd:ee:ff"}, nil))

	dscp := UintParserFactory[uint32](func(f *config_parser.Function, values []uint32, oo *Outbound) error { return nil })
	accepted("dscp", dscp(f("dscp"), "", []string{"8"}, nil))
	rejected("dscp", dscp(f("dscp"), "bogus_param", []string{"8"}, nil))
}
