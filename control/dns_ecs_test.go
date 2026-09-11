/*
*  SPDX-License-Identifier: AGPL-3.0-only
*  Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"bytes"
	"encoding/binary"
	"net"
	"net/netip"
	"testing"

	"github.com/daeuniverse/dae/component/outbound"
	"github.com/daeuniverse/dae/component/outbound/dialer"
	"github.com/daeuniverse/outbound/pool"
	dnsmessage "github.com/miekg/dns"
	"hash/maphash"
)

// mustPackQuery builds a wire-format query with the given extra records.
func mustPackQuery(t *testing.T, extra []dnsmessage.RR) []byte {
	t.Helper()
	m := new(dnsmessage.Msg)
	m.SetQuestion("example.com.", dnsmessage.TypeA)
	m.Extra = extra
	data, err := m.Pack()
	if err != nil {
		t.Fatalf("pack query: %v", err)
	}
	return data
}

func ecsOpt(t *testing.T, opts []dnsmessage.EDNS0) *dnsmessage.OPT {
	t.Helper()
	return &dnsmessage.OPT{
		Hdr:    dnsmessage.RR_Header{Name: ".", Rrtype: dnsmessage.TypeOPT},
		Option: opts,
	}
}

func makeEcsOption(family uint16, netmask uint8, addr net.IP) dnsmessage.EDNS0 {
	return &dnsmessage.EDNS0_SUBNET{
		Code:          dnsmessage.EDNS0SUBNET,
		Family:        family,
		SourceNetmask: netmask,
		SourceScope:   0,
		Address:       addr,
	}
}

// mustUnpack re-parses a (possibly rewritten) wire message with miekg to
// verify the surgery produced a structurally valid message.
func mustUnpack(t *testing.T, data []byte) *dnsmessage.Msg {
	t.Helper()
	m := new(dnsmessage.Msg)
	if err := m.Unpack(data); err != nil {
		t.Fatalf("rewritten message does not unpack: %v", err)
	}
	return m
}

// findOptEcs extracts the ECS option of the first OPT record after an
// unpack, for field-level assertions.
func findOptEcs(t *testing.T, m *dnsmessage.Msg) *dnsmessage.EDNS0_SUBNET {
	t.Helper()
	for _, rr := range m.Extra {
		if opt, ok := rr.(*dnsmessage.OPT); ok {
			for _, o := range opt.Option {
				if e, ok := o.(*dnsmessage.EDNS0_SUBNET); ok {
					return e
				}
			}
		}
	}
	return nil
}

func TestParseEcs(t *testing.T) {
	if s, err := dialer.ParseEcs(""); err != nil || s != nil {
		t.Fatalf("empty ecs should pass through, got %v %v", s, err)
	}
	s, err := dialer.ParseEcs("strip")
	if err != nil || s == nil || !s.Strip || s.Key != "strip" {
		t.Fatalf("strip: got %v %v", s, err)
	}
	s, err = dialer.ParseEcs("203.0.113.7/24")
	if err != nil || s == nil || s.Strip {
		t.Fatalf("cidr parse: got %v %v", s, err)
	}
	if got := s.Prefix.String(); got != "203.0.113.0/24" {
		t.Fatalf("host bits not masked: %v", got)
	}
	if s.Key != "203.0.113.0/24" {
		t.Fatalf("canonical key: %v", s.Key)
	}
	if _, err = dialer.ParseEcs("2001:db8::/32"); err != nil {
		t.Fatalf("ipv6 cidr: %v", err)
	}
	if _, err = dialer.ParseEcs("not-a-prefix"); err == nil {
		t.Fatal("invalid value should error")
	}
	p, err := dialer.ParseEcs("pass")
	if err != nil || p == nil || !p.PassThrough || p.Key != "pass" {
		t.Fatalf("pass: got %v %v", p, err)
	}
}

func TestParseEcsDefault(t *testing.T) {
	s, err := ParseEcsDefault("strip")
	if err != nil || s == nil || !s.Strip {
		t.Fatalf("strip default: %v %v", s, err)
	}
	if s, err = ParseEcsDefault("pass"); err != nil || s != nil {
		t.Fatalf("pass default: %v %v", s, err)
	}
	if s, err = ParseEcsDefault(""); err != nil || s != nil {
		t.Fatalf("empty default: %v %v", s, err)
	}
	if _, err = ParseEcsDefault("203.0.113.0/24"); err == nil {
		t.Fatal("global CIDR must be rejected (per-exit regions differ)")
	}
	if _, err = ParseEcsDefault("bogus"); err == nil {
		t.Fatal("invalid global value must error")
	}
}

func TestStripEcsRemovesWholeOptWhenOnlyEcs(t *testing.T) {
	data := mustPackQuery(t, []dnsmessage.RR{
		ecsOpt(t, []dnsmessage.EDNS0{makeEcsOption(1, 24, net.IPv4(203, 0, 113, 0))}),
	})
	out, changed := dnsRewriteEcs(data, &dialer.EcsSpec{Strip: true, Key: "strip"})
	if !changed {
		t.Fatal("expected change")
	}
	m := mustUnpack(t, out)
	if got := countOpts(t, m); got != 0 {
		t.Fatalf("OPT should be gone, got %d", got)
	}
	if ar := binary.BigEndian.Uint16(out[10:12]); ar != 0 {
		t.Fatalf("ARCOUNT not decremented: %d", ar)
	}
	if q := m.Question[0]; q.Name != "example.com." || q.Qtype != dnsmessage.TypeA {
		t.Fatalf("question damaged: %+v", q)
	}
}

func TestStripEcsKeepsOptWithOtherOptions(t *testing.T) {
	nsid := &dnsmessage.EDNS0_LOCAL{Code: 3, Data: []byte("nsid")}
	data := mustPackQuery(t, []dnsmessage.RR{
		ecsOpt(t, []dnsmessage.EDNS0{nsid, makeEcsOption(1, 24, net.IPv4(198, 51, 100, 0))}),
	})
	origLen := len(data)
	out, changed := dnsRewriteEcs(data, &dialer.EcsSpec{Strip: true, Key: "strip"})
	if !changed {
		t.Fatal("expected change")
	}
	if len(out) >= origLen {
		t.Fatalf("strip should shrink, %d -> %d", origLen, len(out))
	}
	m := mustUnpack(t, out)
	e := findOptEcs(t, m)
	if e != nil {
		t.Fatal("ECS option still present after strip")
	}
	if countOpts(t, m) != 1 {
		t.Fatal("OPT with remaining options should be kept")
	}
	if ar := binary.BigEndian.Uint16(out[10:12]); ar != 1 {
		t.Fatalf("ARCOUNT must stay 1: %d", ar)
	}
}

func TestStripEcsNoEcsIsNoop(t *testing.T) {
	data := mustPackQuery(t, []dnsmessage.RR{
		ecsOpt(t, []dnsmessage.EDNS0{&dnsmessage.EDNS0_LOCAL{Code: 3, Data: []byte("x")}}),
	})
	out, changed := dnsRewriteEcs(data, &dialer.EcsSpec{Strip: true, Key: "strip"})
	if changed || &out[0] != &data[0] {
		t.Fatal("no-op must return the original slice unchanged")
	}
}

func TestStripNoOptIsNoop(t *testing.T) {
	data := mustPackQuery(t, nil)
	out, changed := dnsRewriteEcs(data, &dialer.EcsSpec{Strip: true, Key: "strip"})
	if changed || &out[0] != &data[0] {
		t.Fatal("query without OPT must pass through")
	}
}

func TestPassThroughPolicyIsNoop(t *testing.T) {
	data := mustPackQuery(t, []dnsmessage.RR{
		ecsOpt(t, []dnsmessage.EDNS0{makeEcsOption(1, 24, net.IPv4(1, 2, 3, 0))}),
	})
	out, changed := dnsRewriteEcs(data, &dialer.EcsSpec{PassThrough: true, Key: "pass"})
	if changed || &out[0] != &data[0] {
		t.Fatal("pass-through policy must leave the query untouched")
	}
}

// The global strip default must rewrite even when the dialer carries no
// annotation (the resolution path dialSend actually uses).
func TestResolveEcsPolicyFallsBackToGlobal(t *testing.T) {
	c := &DnsController{}
	if s := c.resolveEcsPolicy(nil, nil); s != nil {
		t.Fatal("nil default should resolve to pass-through")
	}
	c.ecsDefaultSpec = &dialer.EcsSpec{Strip: true, Key: "strip"}
	if s := c.resolveEcsPolicy(nil, nil); s == nil || !s.Strip {
		t.Fatal("global strip default should apply without annotation")
	}
}

func TestSetEcsInjectsOptWhenMissing(t *testing.T) {
	data := mustPackQuery(t, nil)
	prefix := netip.MustParsePrefix("203.0.113.0/24")
	out, changed := dnsRewriteEcs(data, &dialer.EcsSpec{Prefix: prefix, Key: prefix.String()})
	if !changed {
		t.Fatal("expected injection")
	}
	m := mustUnpack(t, out)
	e := findOptEcs(t, m)
	if e == nil {
		t.Fatal("ECS option missing after injection")
	}
	if e.Family != 1 || e.SourceNetmask != 24 || e.SourceScope != 0 {
		t.Fatalf("wrong ECS fields: %+v", e)
	}
	if !e.Address.Equal(net.IPv4(203, 0, 113, 0)) {
		t.Fatalf("wrong ECS address: %v", e.Address)
	}
	for _, rr := range m.Extra {
		if opt, ok := rr.(*dnsmessage.OPT); ok {
			if opt.UDPSize() != dnsInjectedUdpSize {
				t.Fatalf("injected OPT udp size = %d, want %d", opt.UDPSize(), dnsInjectedUdpSize)
			}
		}
	}
	if ar := binary.BigEndian.Uint16(out[10:12]); ar != 1 {
		t.Fatalf("ARCOUNT not incremented: %d", ar)
	}
}

func TestSetEcsReplacesExisting(t *testing.T) {
	data := mustPackQuery(t, []dnsmessage.RR{
		ecsOpt(t, []dnsmessage.EDNS0{
			&dnsmessage.EDNS0_LOCAL{Code: 65001, Data: []byte("keepme")},
			makeEcsOption(1, 24, net.IPv4(1, 2, 3, 0)),
		}),
	})
	prefix := netip.MustParsePrefix("2001:db8:aa::/48")
	out, changed := dnsRewriteEcs(data, &dialer.EcsSpec{Prefix: prefix, Key: prefix.String()})
	if !changed {
		t.Fatal("expected replacement")
	}
	m := mustUnpack(t, out)
	e := findOptEcs(t, m)
	if e == nil || e.Family != 2 || e.SourceNetmask != 48 {
		t.Fatalf("ECS not replaced correctly: %+v", e)
	}
	// The unrelated option must survive the surgery.
	found := false
	for _, rr := range m.Extra {
		if opt, ok := rr.(*dnsmessage.OPT); ok {
			for _, o := range opt.Option {
				if l, ok := o.(*dnsmessage.EDNS0_LOCAL); ok && string(l.Data) == "keepme" {
					found = true
				}
			}
		}
	}
	if !found {
		t.Fatal("unrelated EDNS0 option was dropped")
	}
}

// The no-op path must be allocation-free: the new-option buffer is a
// stack array (a non-constant-length make would heap-allocate even
// without escaping). Guards against regressing to make().
// The most common path — an ECS-free client query forwarded under the
// global strip default — must not allocate at all: annotation map miss,
// no OPT record found (input returned as-is), cache key mixing via
// maphash only.
func TestEcsCommonPathNoAlloc(t *testing.T) {
	data := mustPackQuery(t, nil) // no OPT, arcount=0
	c := &DnsController{dnsCacheHashSeed: maphash.MakeSeed()}
	c.ecsDefaultSpec = &dialer.EcsSpec{Strip: true, Key: "strip"}
	g := outbound.NewDialerGroup(&dialer.GlobalOption{}, "ecs-alloc-test", nil, nil, dialer.DialerSelectionPolicy{}, nil)
	d := &dialer.Dialer{}
	avg := testing.AllocsPerRun(1000, func() {
		spec := c.resolveEcsPolicy(g, d)
		if spec == nil || !spec.Strip {
			t.Fatal("strip default must resolve without annotation")
		}
		if rewritten, changed := dnsRewriteEcs(data, spec); changed || &rewritten[0] != &data[0] {
			t.Fatal("ECS-free query must pass through untouched")
		}
		_ = c.GetHashKey("www.example.com", 1, g, d)
	})
	if avg != 0 {
		t.Fatalf("common path allocates %.2f objects/run; want 0", avg)
	}
}

func TestSetEcsIdenticalNoAlloc(t *testing.T) {
	data := mustPackQuery(t, []dnsmessage.RR{
		ecsOpt(t, []dnsmessage.EDNS0{makeEcsOption(1, 24, net.IPv4(203, 0, 113, 0))}),
	})
	prefix := netip.MustParsePrefix("203.0.113.0/24")
	avg := testing.AllocsPerRun(200, func() {
		out, changed := dnsSetEcs(data, prefix)
		if changed || &out[0] != &data[0] {
			t.Fatal("identical ECS must be a no-op")
		}
	})
	if avg != 0 {
		t.Fatalf("identical no-op path allocates %.2f objects/run; optBuf must stay on the stack", avg)
	}
}

func TestSetEcsIdenticalIsNoop(t *testing.T) {
	ecs := makeEcsOption(1, 24, net.IPv4(203, 0, 113, 0))
	data := mustPackQuery(t, []dnsmessage.RR{ecsOpt(t, []dnsmessage.EDNS0{ecs})})
	out, changed := dnsRewriteEcs(data, &dialer.EcsSpec{Prefix: netip.MustParsePrefix("203.0.113.0/24"), Key: "203.0.113.0/24"})
	if changed || &out[0] != &data[0] {
		t.Fatal("identical ECS must be a no-op returning the original slice")
	}
}

// Rewrite paths (strip-hit and cidr-append) hand out pooled buffers;
// with the pool warm, even the changing paths must not allocate.
func TestEcsRewritePathsPooledNoAlloc(t *testing.T) {
	withEcs := mustPackQuery(t, []dnsmessage.RR{
		ecsOpt(t, []dnsmessage.EDNS0{makeEcsOption(1, 24, net.IPv4(198, 51, 100, 0))}),
	})
	withoutOpt := mustPackQuery(t, nil)
	strip := &dialer.EcsSpec{Strip: true, Key: "strip"}
	cidr := &dialer.EcsSpec{Prefix: netip.MustParsePrefix("2001:db8:aa::/48"), Key: "2001:db8:aa::/48"}

	// Warm every pool bucket used below and keep cycling the buffers so
	// the measured loop only ever hits the pool.
	for i := 0; i < 64; i++ {
		if out, changed := dnsRewriteEcs(withEcs, strip); !changed {
			t.Fatal("strip should remove the ECS option")
		} else {
			pool.PutBuffer(out)
		}
		if out, changed := dnsRewriteEcs(withoutOpt, cidr); !changed {
			t.Fatal("cidr should inject an OPT+ECS option")
		} else {
			pool.PutBuffer(out)
		}
	}
	avg := testing.AllocsPerRun(500, func() {
		if out, changed := dnsRewriteEcs(withEcs, strip); !changed {
			t.Fatal("strip should remove the ECS option")
		} else {
			pool.PutBuffer(out)
		}
		if out, changed := dnsRewriteEcs(withoutOpt, cidr); !changed {
			t.Fatal("cidr should inject an OPT+ECS option")
		} else {
			pool.PutBuffer(out)
		}
	})
	if avg != 0 {
		t.Fatalf("pooled rewrite paths allocate %.2f objects/run; want 0 with a warm pool", avg)
	}
}

func TestSetEcsMasksHostBits(t *testing.T) {
	data := mustPackQuery(t, nil)
	out, changed := dnsRewriteEcs(data, &dialer.EcsSpec{
		Prefix: netip.MustParsePrefix("203.0.113.77/24"), Key: "203.0.113.0/24",
	})
	if !changed {
		t.Fatal("expected change")
	}
	m := mustUnpack(t, out)
	e := findOptEcs(t, m)
	if e == nil || !e.Address.Equal(net.IPv4(203, 0, 113, 0)) {
		t.Fatalf("host bits leaked into ECS: %+v", e)
	}
}

func TestInputNeverMutated(t *testing.T) {
	snapshot := func(b []byte) []byte { cp := append([]byte(nil), b...); return cp }
	data := mustPackQuery(t, []dnsmessage.RR{
		ecsOpt(t, []dnsmessage.EDNS0{makeEcsOption(1, 24, net.IPv4(1, 2, 3, 0))}),
	})
	before := snapshot(data)
	_, _ = dnsRewriteEcs(data, &dialer.EcsSpec{Strip: true, Key: "strip"})
	if !bytes.Equal(data, before) {
		t.Fatal("strip mutated the input buffer")
	}
	out, _ := dnsRewriteEcs(data, &dialer.EcsSpec{Prefix: netip.MustParsePrefix("203.0.113.0/24"), Key: "k"})
	if !bytes.Equal(data, before) {
		t.Fatal("set mutated the input buffer")
	}
	_ = out
}

func TestRoundtripStripAfterSet(t *testing.T) {
	data := mustPackQuery(t, nil)
	prefix := netip.MustParsePrefix("198.51.100.0/24")
	set, _ := dnsRewriteEcs(data, &dialer.EcsSpec{Prefix: prefix, Key: prefix.String()})
	back, changed := dnsRewriteEcs(set, &dialer.EcsSpec{Strip: true, Key: "strip"})
	if !changed {
		t.Fatal("strip after set should change the message")
	}
	m := mustUnpack(t, back)
	if findOptEcs(t, m) != nil {
		t.Fatal("ECS survived the strip-after-set roundtrip")
	}
	if len(back) != len(data) {
		t.Fatalf("roundtrip length %d != original %d", len(back), len(data))
	}
}

func TestMalformedInputNeverPanics(t *testing.T) {
	specs := []*dialer.EcsSpec{
		{Strip: true, Key: "strip"},
		{Prefix: netip.MustParsePrefix("203.0.113.0/24"), Key: "k"},
	}
	garbage := [][]byte{
		{},
		{0, 0, 0},
		make([]byte, 12),
		{0, 1, 1, 0, 0, 1, 0, 0, 0, 0, 0, 99}, // bad ARCOUNT
		append(make([]byte, 12), 0x00, 0, 41, 0, 1, 0, 0, 0), // truncated OPT
	}
	for i, g := range garbage {
		for _, s := range specs {
			out, changed := dnsRewriteEcs(g, s)
			if len(out) == 0 && changed {
				t.Fatalf("case %d: empty output marked as changed", i)
			}
		}
	}
}

func TestMalformedOptDoesNotCrash(t *testing.T) {
	// OPT whose RDLENGTH lies about the message size.
	data := mustPackQuery(t, nil)
	data = append(data, 0x00, 0, 41, 0xff, 0xff, 0, 0, 0, 0, 0x7f, 0xff)
	for _, s := range []*dialer.EcsSpec{
		{Strip: true, Key: "strip"},
		{Prefix: netip.MustParsePrefix("203.0.113.0/24"), Key: "k"},
	} {
		_, _ = dnsRewriteEcs(data, s)
	}
}

func TestMixDnsAnnotationKey(t *testing.T) {
	seed := maphash.MakeSeed()
	base := uint64(0x1234)
	legacy := uint64(0x1234)
	stripDef := &dialer.EcsSpec{Strip: true, Key: "strip"}

	// No annotation, no global default: legacy key untouched.
	if got, isolated := mixDnsAnnotationKey(base, seed, nil, nil); got != legacy || isolated {
		t.Fatal("nil annotation and nil default must not mix or isolate")
	}

	// No annotation, global strip default: policy key mixed (still shared).
	gotDef, isoDef := mixDnsAnnotationKey(base, seed, nil, stripDef)
	if isoDef || gotDef == base {
		t.Fatal("global default should mix without isolating")
	}

	tagOnly := &dialer.Annotation{DnsCacheTag: "sg"}
	hTag, isolated := mixDnsAnnotationKey(base, seed, tagOnly, nil)
	if !isolated || hTag == base {
		t.Fatal("tag should mix and isolate")
	}

	// Same tag, different ECS => different keys (no wrong answer reuse).
	ecsA := &dialer.Annotation{DnsCacheTag: "sg", Ecs: &dialer.EcsSpec{Strip: true, Key: "strip"}}
	ecsB := &dialer.Annotation{DnsCacheTag: "sg", Ecs: &dialer.EcsSpec{Prefix: netip.MustParsePrefix("203.0.113.0/24"), Key: "203.0.113.0/24"}}
	hA, isoA := mixDnsAnnotationKey(base, seed, ecsA, stripDef)
	hB, isoB := mixDnsAnnotationKey(base, seed, ecsB, stripDef)
	if !isoA || !isoB {
		t.Fatal("ecs+tag annotations should isolate")
	}
	if hA == hB {
		t.Fatal("different ECS policies under the same tag must not share a cache key")
	}
	if hA == hTag || hB == hTag {
		t.Fatal("ecs variants must differ from the tag-only key")
	}

	// Annotation 'pass' overrides the global strip default.
	ecsPass := &dialer.Annotation{DnsCacheTag: "sg", Ecs: &dialer.EcsSpec{PassThrough: true, Key: "pass"}}
	hPass, isoPass := mixDnsAnnotationKey(base, seed, ecsPass, stripDef)
	if !isoPass || hPass == hA || hPass == hB || hPass == hTag {
		t.Fatal("explicit pass must get its own key distinct from strip/cidr/tag-only")
	}
}

// GetHashKey without annotations must produce the legacy formula
// seed(qname) ^ qtype<<32 (no outbound pointer mixing, no extras).
func TestGetHashKeyLegacyUnchanged(t *testing.T) {
	c := &DnsController{dnsCacheHashSeed: maphash.MakeSeed()}
	got := c.GetHashKey("example.com.", 1, nil, nil)
	want := HashKey(maphash.String(c.dnsCacheHashSeed, "example.com.") ^ uint64(1)<<32)
	if got != want {
		t.Fatalf("legacy key changed: got %#x want %#x", got, want)
	}
}

func countOpts(t *testing.T, m *dnsmessage.Msg) int {
	t.Helper()
	n := 0
	for _, rr := range m.Extra {
		if _, ok := rr.(*dnsmessage.OPT); ok {
			n++
		}
	}
	return n
}
