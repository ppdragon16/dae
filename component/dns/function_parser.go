/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package dns

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/daeuniverse/dae/component/routing"
	"github.com/daeuniverse/dae/pkg/config_parser"
	dnsmessage "github.com/miekg/dns"
)

// RCodeParserFactory parses the rcode operands: DNS response codes by name
// (`rcode(NXDOMAIN)`, case-insensitive) or by number (`rcode(3)`). Like qtype,
// operands are bare values; a named parameter would be read as one more
// operand and build a different rule from a typo.
func RCodeParserFactory(callback func(f *config_parser.Function, rcodes []uint16, overrideOutbound *routing.Outbound) (err error)) routing.FunctionParser {
	return routing.EmptyKeyPlainParserFactory(func(f *config_parser.Function, paramValueGroup []string, overrideOutbound *routing.Outbound) (err error) {
		var rcodes []uint16
		for _, v := range paramValueGroup {
			if r, ok := dnsmessage.StringToRcode[strings.ToUpper(v)]; ok {
				rcodes = append(rcodes, uint16(r))
				continue
			}
			if val, err := strconv.ParseUint(v, 0, 16); err == nil {
				rcodes = append(rcodes, uint16(val))
				continue
			}
			return fmt.Errorf("unknown DNS response code: %v", v)
		}
		return callback(f, rcodes, overrideOutbound)
	})
}

// TypeParserFactory parses the qtype operands. The DNS request types are bare
// values (`qtype(1, AAAA)`), so the factory reuses the routing package's
// empty-key contract: a named parameter would otherwise be read as one more
// operand and build a different rule from a typo.
func TypeParserFactory(callback func(f *config_parser.Function, types []uint16, overrideOutbound *routing.Outbound) (err error)) routing.FunctionParser {
	return routing.EmptyKeyPlainParserFactory(func(f *config_parser.Function, paramValueGroup []string, overrideOutbound *routing.Outbound) (err error) {
		var types []uint16
		for _, v := range paramValueGroup {
			if t, ok := dnsmessage.StringToType[strings.ToUpper(v)]; ok {
				types = append(types, t)
				continue
			}
			if val, err := strconv.ParseUint(v, 0, 16); err == nil {
				types = append(types, uint16(val))
				continue
			}
			return fmt.Errorf("unknown DNS request type: %v", v)
		}
		return callback(f, types, overrideOutbound)
	})
}
