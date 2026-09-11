/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package config

import (
	"bytes"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/daeuniverse/dae/pkg/config_parser"
)

func TestMarshal(t *testing.T) {
	t.Skip("Skipping: example.dae intentionally contains deprecated fields for documentation")
	abs, err := filepath.Abs("../example.dae")
	if err != nil {
		t.Fatal(err)
	}
	merger := NewMerger(abs)
	sections, _, err := merger.Merge()
	if err != nil {
		t.Fatal(err)
	}
	conf1, err := New(sections)
	if err != nil {
		t.Fatal(err)
	}
	b, err := conf1.Marshal(2)
	if err != nil {
		t.Fatal(err)
	}
	t.Log(string(b))
	// Read it again.
	if err = os.WriteFile("/tmp/test.dae", b, 0640); err != nil {
		t.Fatal(err)
	}
	sections, _, err = NewMerger("/tmp/test.dae").Merge()
	if err != nil {
		t.Fatal(err)
	}
	conf2, err := New(sections)
	if err != nil {
		t.Fatal(err)
	}

	if !reflect.DeepEqual(conf1, conf2) {
		t.Fatal("not equal")
	}
	if !bytes.Contains(b, []byte(`filter:name("US_node") [add_latency:"-500ms"]`)) {
		t.Fatalf("first marshal dropped or mis-attached US_node annotation\n%s", string(b))
	}
	if bytes.Contains(b, []byte(`filter:name("HK_node") [add_latency:`)) {
		t.Fatalf("first marshal attached add_latency to HK_node\n%s", string(b))
	}
}

func TestMarshalPreservesGroupFilterWithMoreThanFiveParams(t *testing.T) {
	sections, err := config_parser.Parse(`
global {}
group {
    g {
        filter: name(n1, n2, n3, n4, n5, n6)
        filter: name(n1, n2, n3, n4, n5, n6) [add_latency: -500ms]
        policy: min_avg10
    }
}
routing {
    fallback: g
}
`)
	if err != nil {
		t.Fatal(err)
	}
	conf, err := New(sections)
	if err != nil {
		t.Fatal(err)
	}
	if len(conf.Group) != 1 || len(conf.Group[0].Filter) != 2 {
		t.Fatalf("unexpected parsed group filters: %#v", conf.Group)
	}
	if got := len(conf.Group[0].Filter[0][0].Params); got != 6 {
		t.Fatalf("parsed filter params = %d, want 6", got)
	}
	b, err := conf.Marshal(2)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(b, []byte("...")) {
		t.Fatalf("marshal truncated function params:\n%s", string(b))
	}
	if !bytes.Contains(b, []byte("n6")) {
		t.Fatalf("marshal dropped n6:\n%s", string(b))
	}
	if !bytes.Contains(b, []byte("[add_latency:")) {
		t.Fatalf("marshal dropped filter annotation:\n%s", string(b))
	}

	sections2, err := config_parser.Parse(string(b))
	if err != nil {
		t.Fatalf("parse-after-marshal: %v\n%s", err, string(b))
	}
	conf2, err := New(sections2)
	if err != nil {
		t.Fatalf("decode-after-marshal: %v\n%s", err, string(b))
	}
	if len(conf2.Group) != 1 || len(conf2.Group[0].Filter) != 2 {
		t.Fatalf("round-trip group filters: %#v", conf2.Group)
	}
	for i, f := range conf2.Group[0].Filter {
		if len(f) != 1 {
			t.Fatalf("filter[%d] and-functions = %d, want 1", i, len(f))
		}
		if got := len(f[0].Params); got != 6 {
			t.Fatalf("filter[%d] params = %d, want 6 from:\n%s", i, got, string(b))
		}
		if got := f[0].Params[5].Val; got != "n6" {
			t.Fatalf("filter[%d] last param = %q, want n6", i, got)
		}
	}
	if len(conf2.Group[0].FilterAnnotation) != 2 || len(conf2.Group[0].FilterAnnotation[1]) != 1 {
		t.Fatalf("round-trip annotations: %#v", conf2.Group[0].FilterAnnotation)
	}
	if len(conf2.Group[0].FilterAnnotation[0]) != 0 {
		t.Fatalf("first filter picked up annotation: %#v", conf2.Group[0].FilterAnnotation[0])
	}
	if got := conf2.Group[0].FilterAnnotation[1][0]; got.Key != "add_latency" || got.Val != "-500ms" {
		t.Fatalf("round-trip annotation = %#v", conf2.Group[0].FilterAnnotation[1])
	}
}

func TestMarshalPreservesGroupFilterAnnotation(t *testing.T) {
	sections, err := config_parser.Parse(`
global {}
group {
    g {
        filter: name(HK_node)
        filter: name(US_node) [add_latency: -500ms]
        policy: min_avg10
    }
}
routing {
    fallback: g
}
`)
	if err != nil {
		t.Fatal(err)
	}
	conf, err := New(sections)
	if err != nil {
		t.Fatal(err)
	}
	if len(conf.Group) != 1 || len(conf.Group[0].Filter) != 2 || len(conf.Group[0].FilterAnnotation) != 2 {
		t.Fatalf("unexpected parsed group: filters=%d annotations=%d", len(conf.Group[0].Filter), len(conf.Group[0].FilterAnnotation))
	}
	b, err := conf.Marshal(2)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(b, []byte(`filter:name("US_node") [add_latency:"-500ms"]`)) {
		t.Fatalf("marshal dropped or mis-attached US_node annotation:\n%s", string(b))
	}
	if bytes.Contains(b, []byte(`filter:name("HK_node") [add_latency:`)) {
		t.Fatalf("marshal attached add_latency to HK_node:\n%s", string(b))
	}

	sections2, err := config_parser.Parse(string(b))
	if err != nil {
		t.Fatalf("parse-after-marshal: %v\n%s", err, string(b))
	}
	conf2, err := New(sections2)
	if err != nil {
		t.Fatalf("decode-after-marshal: %v\n%s", err, string(b))
	}
	if len(conf2.Group) != 1 || len(conf2.Group[0].FilterAnnotation) != 2 {
		t.Fatalf("round-trip annotations: %#v", conf2.Group)
	}
	if len(conf2.Group[0].FilterAnnotation[0]) != 0 {
		t.Fatalf("HK_node picked up annotation: %#v", conf2.Group[0].FilterAnnotation[0])
	}
	if got := conf2.Group[0].FilterAnnotation[1]; len(got) != 1 || got[0].Key != "add_latency" || got[0].Val != "-500ms" {
		t.Fatalf("US_node annotation = %#v", conf2.Group[0].FilterAnnotation[1])
	}
}

func TestMarshalPreservesRoutingOutboundParams(t *testing.T) {
	sections, err := config_parser.Parse(`
global {}
routing {
    ip(1.1.1.1) -> g(n1, n2, n3, n4, n5, n6)
    fallback: direct
}
`)
	if err != nil {
		t.Fatal(err)
	}
	conf, err := New(sections)
	if err != nil {
		t.Fatal(err)
	}
	if len(conf.Routing.Rules) != 1 {
		t.Fatalf("parsed rules = %d, want 1", len(conf.Routing.Rules))
	}
	if got := len(conf.Routing.Rules[0].Outbound.Params); got != 6 {
		t.Fatalf("parsed outbound params = %d, want 6", got)
	}
	b, err := conf.Marshal(2)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(b, []byte("...")) {
		t.Fatalf("marshal truncated routing outbound:\n%s", string(b))
	}
	if !bytes.Contains(b, []byte("n6")) {
		t.Fatalf("marshal dropped outbound n6:\n%s", string(b))
	}
}

// TestMarshalPolicyFixedListIsSupported pins the interface-field regression: a
// group whose policy is written as a function call (`policy: fixed(0)`) stores
// an any-typed []*config_parser.Function, which marshalLeaf's leaf switch had
// no case for and rejected as an "unknown leaf type". (Port of kdae a4cffe92.)
func TestMarshalPolicyFixedListIsSupported(t *testing.T) {
	sections, err := config_parser.Parse(`
global {}
group {
    g {
        policy: fixed(0)
        filter: name(keyword: hk)
    }
}
routing {
    fallback: g
}
`)
	if err != nil {
		t.Fatal(err)
	}
	conf, err := New(sections)
	if err != nil {
		t.Fatal(err)
	}
	if len(conf.Group) != 1 {
		t.Fatalf("groups = %d, want 1", len(conf.Group))
	}
	b, err := conf.Marshal(2)
	if err != nil {
		t.Fatalf("Marshal with policy: fixed(N) failed: %v", err)
	}
	if !bytes.Contains(b, []byte("policy:fixed(")) {
		t.Fatalf("marshalled policy line missing:\n%s", string(b))
	}
	// The marshalled config must decode again with the same policy value.
	sections2, err := config_parser.Parse(string(b))
	if err != nil {
		t.Fatalf("parse-after-marshal: %v\n%s", err, string(b))
	}
	conf2, err := New(sections2)
	if err != nil {
		t.Fatalf("decode-after-marshal: %v\n%s", err, string(b))
	}
	if !reflect.DeepEqual(conf.Group[0].Policy, conf2.Group[0].Policy) {
		t.Fatalf("policy changed across round-trip: %#v -> %#v", conf.Group[0].Policy, conf2.Group[0].Policy)
	}
}
