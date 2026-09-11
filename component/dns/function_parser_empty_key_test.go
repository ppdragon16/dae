/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2026, daeuniverse Organization <dae@v2raya.org>
 */

package dns

import (
	"strings"
	"testing"

	"github.com/daeuniverse/dae/component/routing"
	"github.com/daeuniverse/dae/pkg/config_parser"
)

// TestQTypeRejectsNamedParams pins the DNS request type parser on the same
// empty-key contract: qtype operands are bare values, so a named parameter
// must be rejected instead of being folded into the type list. (Port of kdae
// bdba15d3.)
func TestQTypeRejectsNamedParams(t *testing.T) {
	fp := TypeParserFactory(func(f *config_parser.Function, types []uint16, overrideOutbound *routing.Outbound) error {
		return nil
	})
	f := &config_parser.Function{Name: "qtype"}

	if err := fp(f, "", []string{"1", "AAAA"}, nil); err != nil {
		t.Fatalf("bare form must stay accepted, got %v", err)
	}
	err := fp(f, "bogus_param", []string{"AAAA"}, nil)
	if err == nil {
		t.Fatal("qtype: named parameter silently accepted")
	}
	if !strings.Contains(err.Error(), `unsupported parameter key "bogus_param"`) || !strings.Contains(err.Error(), "qtype") {
		t.Fatalf("error should name the function and the rejected key, got %v", err)
	}
}
