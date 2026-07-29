/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package config

import (
	"strings"

	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/pkg/config_parser"
)

type patch func(params *Config) error

var patches = []patch{
	// patchTcpCheckHttpMethod,
	patchEmptyDns,
	patchMustOutbound,
}

// func patchTcpCheckHttpMethod(params *Config) error {
// 	if !common.IsValidHttpMethod(params.Global.TcpCheckHttpMethod) {
// 		log.Warnf("Unknown HTTP Method '%v'. Fallback to 'CONNECT'.", params.Global.TcpCheckHttpMethod)
// 		params.Global.TcpCheckHttpMethod = "CONNECT"
// 	}
// 	return nil
// }

func patchEmptyDns(params *Config) error {
	ApplyEmptyDnsDefaults(&params.Dns)
	return nil
}

func patchMustOutbound(params *Config) error {
	ApplyMustOutboundRewrite(&params.Routing)
	return nil
}

// ApplyEmptyDnsDefaults fills in the same DNS routing fallback defaults
// that config.New() applies via patches. Exported so that hot-update
// paths (update-dns) can obtain the same result without parsing the
// full Config.
func ApplyEmptyDnsDefaults(dns *Dns) {
	if dns.Routing.Request.Fallback == nil {
		dns.Routing.Request.Fallback = consts.DnsRequestOutboundIndex_AsIs.String()
	}
	if dns.Routing.Response.Fallback == nil {
		dns.Routing.Response.Fallback = consts.DnsResponseOutboundIndex_Accept.String()
	}
}

// ApplyMustOutboundRewrite rewrites must_<name> outbound references
// (e.g. must_direct) to <name>(must) so that the routing matcher can
// resolve the base name against the outbound name→id map.
// Exported for the same reason as ApplyEmptyDnsDefaults.
func ApplyMustOutboundRewrite(routing *Routing) {
	for i := range routing.Rules {
		if strings.HasPrefix(routing.Rules[i].Outbound.Name, "must_") {
			if routing.Rules[i].Outbound.Name == "must_rules" {
				continue
			}
			routing.Rules[i].Outbound.Name = strings.TrimPrefix(routing.Rules[i].Outbound.Name, "must_")
			routing.Rules[i].Outbound.Params = append(routing.Rules[i].Outbound.Params, &config_parser.Param{
				Val: "must",
			})
		}
	}
	if f := FunctionOrStringToFunction(routing.Fallback); strings.HasPrefix(f.Name, "must_") {
		f.Name = strings.TrimPrefix(f.Name, "must_")
		f.Params = append(f.Params, &config_parser.Param{
			Val: "must",
		})
		routing.Fallback = f
	}
}
