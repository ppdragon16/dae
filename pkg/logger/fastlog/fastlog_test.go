/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package fastlog

import (
	"bytes"
	"net/netip"
	"strings"
	"sync"
	"testing"

	log "github.com/sirupsen/logrus"
)

func mustAddrPort(s string) netip.AddrPort {
	ap, err := netip.ParseAddrPort(s)
	if err != nil {
		panic(err)
	}
	return ap
}

func makePname(s string) [16]uint8 {
	var p [16]uint8
	copy(p[:], s)
	return p
}

func makeMac(s string) [6]uint8 {
	// Parse "aa:bb:cc:dd:ee:ff" format with simple hex decode
	var mac [6]uint8
	for i := 0; i < 6 && i*3+2 <= len(s); i++ {
		hi := s[i*3]
		lo := s[i*3+1]
		if hi >= 'a' {
			hi -= 'a' - 10
		} else if hi >= 'A' {
			hi -= 'A' - 10
		} else {
			hi -= '0'
		}
		if lo >= 'a' {
			lo -= 'a' - 10
		} else if lo >= 'A' {
			lo -= 'A' - 10
		} else {
			lo -= '0'
		}
		mac[i] = hi<<4 | lo
	}
	return mac
}

func TestLogDialFormat(t *testing.T) {
	var buf bytes.Buffer
	Configure(&buf)

	LogDial(
		mustAddrPort("192.168.1.1:54321"),
		mustAddrPort("1.2.3.4:443"),
		"tcp4", "example.com",
		makePname("curl"), makeMac("aa:bb:cc:dd:ee:ff"),
		1234, 2, 0,
		false,  // controlPlaneRoute
		false,  // fallbackIpVersion
		"1.2.3.4:443",
		false,  // fallback
		"my-out", "min_moving_avg", "my-dialer",
		"", "", "",
	)

	output := buf.String()
	t.Logf("LogDial output:\n%s", output)

	checks := []string{
		`level=info`,
		`[TCP4] 192.168.1.1:54321 <-> 1.2.3.4:443`,
		`network=tcp4`,
		`sniffed=example.com`,
		`ip="1.2.3.4:443"`,
		`pid=1234`,
		`ifindex=2`,
		`dscp=0`,
		`pname=curl`,
		`mac="aa:bb:cc:dd:ee:ff"`,
		`outbound=my-out`,
		`policy="min_moving_avg"`,
		`dialer=my-dialer`,
	}
	for _, check := range checks {
		if !strings.Contains(output, check) {
			t.Errorf("output missing %q", check)
		}
	}

	if !strings.Contains(output, `time="`) {
		t.Error("output missing time=\" prefix")
	}
}

func TestLogDialFallback(t *testing.T) {
	var buf bytes.Buffer
	Configure(&buf)

	LogDial(
		mustAddrPort("192.168.1.1:54321"),
		mustAddrPort("1.2.3.4:443"),
		"tcp4", "example.com",
		makePname("curl"), makeMac("aa:bb:cc:dd:ee:ff"),
		1234, 2, 0,
		false, // controlPlaneRoute
		false, // fallbackIpVersion
		"1.2.3.4:443",
		true, // fallback
		"", "", "", // not used when fallback=true
		"orig-out", "orig-policy", "fb-dialer",
	)

	output := buf.String()
	t.Logf("LogDial fallback output:\n%s", output)

	checks := []string{
		`<-(fallback)->`,
		`originalOutbound=orig-out`,
		`originalPolicy=orig-policy`,
		`fallbackDialer=fb-dialer`,
	}
	for _, check := range checks {
		if !strings.Contains(output, check) {
			t.Errorf("output missing %q", check)
		}
	}

	// Should NOT contain non-fallback-specific fields
	if strings.Contains(output, ` outbound=`) {
		t.Error("fallback output should not contain outbound=")
	}
	if strings.Contains(output, ` dialer=`) {
		t.Error("fallback output should not contain dialer=")
	}
}

func TestLogDialControlPlaneRoute(t *testing.T) {
	var buf bytes.Buffer
	Configure(&buf)

	LogDial(
		mustAddrPort("192.168.1.1:54321"),
		mustAddrPort("1.2.3.4:443"),
		"tcp4", "example.com",
		makePname("curl"), makeMac("aa:bb:cc:dd:ee:ff"),
		1234, 2, 0,
		true, // controlPlaneRoute
		false,
		"1.2.3.4:443",
		false,
		"my-out", "min_moving_avg", "my-dialer",
		"", "", "",
	)

	output := buf.String()
	if !strings.Contains(output, `controlPlaneRoute=true`) {
		t.Errorf("output missing controlPlaneRoute=true:\n%s", output)
	}
}

func TestLogDialFallbackIpVersion(t *testing.T) {
	var buf bytes.Buffer
	Configure(&buf)

	LogDial(
		mustAddrPort("192.168.1.1:54321"),
		mustAddrPort("1.2.3.4:443"),
		"tcp4", "example.com",
		makePname("curl"), makeMac("aa:bb:cc:dd:ee:ff"),
		1234, 2, 0,
		false, // controlPlaneRoute
		true,  // fallbackIpVersion
		"1.2.3.4:443",
		false,
		"my-out", "min_moving_avg", "my-dialer",
		"", "", "",
	)

	output := buf.String()
	if !strings.Contains(output, `[TCP4 (fallback)]`) {
		t.Errorf("output missing fallback IP version label:\n%s", output)
	}
}

func TestLogDnsResponseFormat(t *testing.T) {
	var buf bytes.Buffer
	Configure(&buf)

	LogDnsResponse(
		mustAddrPort("192.168.1.1:54321"),
		mustAddrPort("8.8.8.8:53"),
		false, // not TCP
		mustAddrPort("8.8.8.8:53"), // same as dst
		"udp4", "my-out", "min_moving_avg", "my-dialer",
		"example.com", 1,
		makePname("curl"), makeMac("aa:bb:cc:dd:ee:ff"),
		1234, 2, 0,
		true, // accepted
	)

	output := buf.String()
	t.Logf("LogDnsResponse output:\n%s", output)

	checks := []string{
		`level=info`,
		`[DNS] 192.168.1.1:54321 <-> 8.8.8.8:53`,
		`network=udp4`,
		`outbound=my-out`,
		`policy="min_moving_avg"`,
		`dialer=my-dialer`,
		`qname=example.com`,
		`qtype=1`,
		`pid=1234`,
		`ifindex=2`,
		`dscp=0`,
		`pname=curl`,
		`mac="aa:bb:cc:dd:ee:ff"`,
	}
	for _, check := range checks {
		if !strings.Contains(output, check) {
			t.Errorf("output missing %q", check)
		}
	}
}

func TestLogDnsResponseTcp(t *testing.T) {
	var buf bytes.Buffer
	Configure(&buf)

	LogDnsResponse(
		mustAddrPort("192.168.1.1:54321"),
		mustAddrPort("8.8.8.8:53"),
		true, // TCP
		mustAddrPort("8.8.8.8:53"),
		"tcp4", "my-out", "min_moving_avg", "my-dialer",
		"example.com", 1,
		makePname("curl"), makeMac("aa:bb:cc:dd:ee:ff"),
		1234, 2, 0,
		true,
	)

	output := buf.String()
	if !strings.Contains(output, `[DNS(TCP)]`) {
		t.Errorf("output missing [DNS(TCP)]:\n%s", output)
	}
}

func TestLogDnsResponseDifferentTarget(t *testing.T) {
	var buf bytes.Buffer
	Configure(&buf)

	// actual target differs from original dst
	LogDnsResponse(
		mustAddrPort("192.168.1.1:54321"),
		mustAddrPort("8.8.8.8:53"),
		false,
		mustAddrPort("1.1.1.1:53"), // different actual target
		"udp4", "my-out", "min_moving_avg", "my-dialer",
		"example.com", 1,
		makePname("curl"), makeMac("aa:bb:cc:dd:ee:ff"),
		1234, 2, 0,
		true,
	)

	output := buf.String()
	if !strings.Contains(output, `1.1.1.1:53 (8.8.8.8:53)`) {
		t.Errorf("output missing alternate target format:\n%s", output)
	}
}

func TestLogDnsResponseReject(t *testing.T) {
	var buf bytes.Buffer
	Configure(&buf)

	LogDnsResponse(
		mustAddrPort("192.168.1.1:54321"),
		mustAddrPort("8.8.8.8:53"),
		false,
		mustAddrPort("8.8.8.8:53"),
		"udp4", "my-out", "min_moving_avg", "my-dialer",
		"example.com", 1,
		makePname("curl"), makeMac("aa:bb:cc:dd:ee:ff"),
		1234, 2, 0,
		false, // rejected
	)

	output := buf.String()
	if !strings.Contains(output, `Reject with empty answer`) {
		t.Errorf("output missing rejection message:\n%s", output)
	}
}

func TestConcurrentSafety(t *testing.T) {
	var buf bytes.Buffer
	Configure(&buf)

	const goroutines = 50
	const iterations = 200
	var wg sync.WaitGroup
	wg.Add(goroutines)

	for g := 0; g < goroutines; g++ {
		go func() {
			defer wg.Done()
			for i := 0; i < iterations; i++ {
				LogDial(
					mustAddrPort("192.168.1.1:54321"),
					mustAddrPort("1.2.3.4:443"),
					"tcp4", "example.com",
					makePname("curl"), makeMac("aa:bb:cc:dd:ee:ff"),
					1234, 2, 0,
					false, false,
					"1.2.3.4:443",
					false,
					"my-out", "min_moving_avg", "my-dialer",
					"", "", "",
				)
			}
		}()
	}

	wg.Wait()

	output := buf.String()
	lines := strings.Split(strings.TrimSuffix(output, "\n"), "\n")
	if len(lines) != goroutines*iterations {
		t.Errorf("expected %d lines, got %d", goroutines*iterations, len(lines))
	}

	for _, line := range lines {
		if line == "" {
			continue
		}
		if strings.Count(line, "\n") > 0 {
			t.Errorf("line contains embedded newline: %q", line)
		}
	}
}

func TestTimestampCaching(t *testing.T) {
	var buf bytes.Buffer
	Configure(&buf)

	call := func() string {
		LogDial(
			mustAddrPort("192.168.1.1:54321"),
			mustAddrPort("1.2.3.4:443"),
			"tcp4", "",
			makePname(""), makeMac("00:00:00:00:00:00"),
			0, 0, 0,
			false, false,
			"1.2.3.4:443",
			false,
			"", "", "",
			"", "", "",
		)
		s := buf.String()
		buf.Reset()
		return s
	}

	firstLine := call()
	secondLine := call()

	extractTs := func(s string) string {
		start := strings.Index(s, `time="`)
		if start < 0 {
			return ""
		}
		start += len(`time="`)
		end := strings.Index(s[start:], `"`)
		if end < 0 {
			return ""
		}
		return s[start : start+end]
	}

	ts1 := extractTs(firstLine)
	ts2 := extractTs(secondLine)

	if ts1 == "" || ts2 == "" {
		t.Fatal("failed to extract timestamps")
	}
	if ts1 != ts2 {
		t.Logf("timestamps differ (expected same within 1s): %q vs %q", ts1, ts2)
	}
	if len(ts1) == 0 {
		t.Error("empty timestamp")
	}
}

func TestUtf8Encoding(t *testing.T) {
	var buf bytes.Buffer
	Configure(&buf)

	LogDnsResponse(
		mustAddrPort("192.168.1.1:54321"),
		mustAddrPort("8.8.8.8:53"),
		false,
		mustAddrPort("8.8.8.8:53"),
		"udp4", "my-out", "min_moving_avg", "my-dialer",
		"中文.example.com", 1,
		makePname("curl"), makeMac("aa:bb:cc:dd:ee:ff"),
		1234, 2, 0,
		true,
	)

	output := buf.String()
	t.Logf("UTF-8 DNS response output:\n%s", output)

	if !strings.Contains(output, `qname="中文.example.com"`) {
		t.Errorf("UTF-8 qname not found or incorrectly formatted in output")
	}

	buf.Reset()

	LogDial(
		mustAddrPort("192.168.1.1:54321"),
		mustAddrPort("1.2.3.4:443"),
		"tcp4", "中文站点.com",
		makePname("谷歌浏览器"), makeMac("aa:bb:cc:dd:ee:ff"),
		1234, 2, 0,
		false, false,
		"1.2.3.4:443",
		false,
		"my-out", "min_moving_avg", "my-dialer",
		"", "", "",
	)

	output = buf.String()
	t.Logf("UTF-8 dial output:\n%s", output)

	if !strings.Contains(output, `sniffed="中文站点.com"`) {
		t.Errorf("UTF-8 sniffed domain not found or incorrectly formatted")
	}
	if !strings.Contains(output, `pname="谷歌浏览器"`) {
		t.Errorf("UTF-8 pname not found or incorrectly formatted")
	}
}

func TestUtf8RoundTrip(t *testing.T) {
	inputs := []struct {
		val      string
		expected string
	}{
		{"hello", "key=hello"},
		{"hello world", `key="hello world"`},
		{"中文", `key="中文"`},
		{"日本語", `key="日本語"`},
	}

	for _, tc := range inputs {
		buf := appendStr(nil, "key", tc.val)
		got := string(buf)
		if got != " "+tc.expected {
			t.Errorf("appendStr(%q) = %q, want %q", tc.val, got, " "+tc.expected)
		}
	}
}

func TestNeedsQuote(t *testing.T) {
	tests := []struct {
		s    string
		want bool
	}{
		{"", true},
		{"abc", false},
		{"hello123", false},
		{"hello-world", false},
		{"example.com", false},
		{"hello world", true},
		{"key=value", true},
		{"中文", true},
		{"café", true},
	}
	for _, tc := range tests {
		got := needsQuote(tc.s)
		if got != tc.want {
			t.Errorf("needsQuote(%q) = %v, want %v", tc.s, got, tc.want)
		}
	}
}

func TestAppendMac(t *testing.T) {
	mac := [6]uint8{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff}
	buf := appendMac(nil, mac)
	if string(buf) != "aa:bb:cc:dd:ee:ff" {
		t.Errorf("appendMac = %q, want %q", string(buf), "aa:bb:cc:dd:ee:ff")
	}
}

func TestAppendPname(t *testing.T) {
	// Normal name
	pname := makePname("curl")
	buf := appendPname(nil, pname)
	if string(buf) != "curl" {
		t.Errorf("appendPname = %q, want %q", string(buf), "curl")
	}

	// Name shorter than 16 bytes (null terminated)
	var pname2 [16]uint8
	copy(pname2[:], "python")
	buf2 := appendPname(nil, pname2)
	if string(buf2) != "python" {
		t.Errorf("appendPname = %q, want %q", string(buf2), "python")
	}
}

func TestAppendAddrPort(t *testing.T) {
	ap := mustAddrPort("1.2.3.4:443")
	buf := appendAddrPort(nil, ap)
	if string(buf) != "1.2.3.4:443" {
		t.Errorf("appendAddrPort = %q, want %q", string(buf), "1.2.3.4:443")
	}

	// IPv6
	ap6 := mustAddrPort("[::1]:53")
	buf6 := appendAddrPort(nil, ap6)
	if string(buf6) != "[::1]:53" {
		t.Errorf("appendAddrPort = %q, want %q", string(buf6), "[::1]:53")
	}
}

func TestAppendSource(t *testing.T) {
	src := mustAddrPort("192.168.1.1:54321")
	dst := mustAddrPort("8.8.8.8:53")

	// Different addresses
	buf := appendSource(nil, src, dst.Addr())
	if string(buf) != "192.168.1.1:54321" {
		t.Errorf("appendSource(different) = %q, want %q", string(buf), "192.168.1.1:54321")
	}

	// Same address (localhost)
	buf2 := appendSource(nil, src, src.Addr())
	if string(buf2) != "localhost:54321" {
		t.Errorf("appendSource(same) = %q, want %q", string(buf2), "localhost:54321")
	}
}

// Benchmarks

func BenchmarkFastLogDial(b *testing.B) {
	var buf bytes.Buffer
	Configure(&buf)
	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		LogDial(
			mustAddrPort("192.168.1.1:54321"),
			mustAddrPort("1.2.3.4:443"),
			"tcp4", "example.com",
			makePname("curl"), makeMac("aa:bb:cc:dd:ee:ff"),
			1234, 2, 0,
			false, false,
			"1.2.3.4:443",
			false,
			"my-out", "min_moving_avg", "my-dialer",
			"", "", "",
		)
	}
}

func BenchmarkLogrusLogDial(b *testing.B) {
	var buf bytes.Buffer
	log.SetOutput(&buf)
	log.SetLevel(log.InfoLevel)
	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		log.WithFields(log.Fields{
			"network":  "tcp4",
			"sniffed":  "example.com",
			"ip":       "1.2.3.4:443",
			"pid":      uint32(1234),
			"ifindex":  uint32(2),
			"dscp":     uint8(0),
			"pname":    "curl",
			"mac":      "aa:bb:cc:dd:ee:ff",
			"outbound": "my-out",
			"policy":   "min_moving_avg",
			"dialer":   "my-dialer",
		}).Info("[TCP4] 192.168.1.1:54321 <-> 1.2.3.4:443")
	}
}

func BenchmarkFastLogDnsResponse(b *testing.B) {
	var buf bytes.Buffer
	Configure(&buf)
	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		LogDnsResponse(
			mustAddrPort("192.168.1.1:54321"),
			mustAddrPort("8.8.8.8:53"),
			false,
			mustAddrPort("8.8.8.8:53"),
			"udp4", "my-out", "min_moving_avg", "my-dialer",
			"example.com", 1,
			makePname("curl"), makeMac("aa:bb:cc:dd:ee:ff"),
			1234, 2, 0,
			true,
		)
	}
}

func BenchmarkLogrusLogDnsResponse(b *testing.B) {
	var buf bytes.Buffer
	log.SetOutput(&buf)
	log.SetLevel(log.InfoLevel)
	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		log.WithFields(log.Fields{
			"network":  "udp4",
			"outbound": "my-out",
			"policy":   "min_moving_avg",
			"dialer":   "my-dialer",
			"qname":    "example.com",
			"qtype":    uint16(1),
			"pid":      uint32(1234),
			"ifindex":  uint32(2),
			"dscp":     uint8(0),
			"pname":    "curl",
			"mac":      "aa:bb:cc:dd:ee:ff",
		}).Info("[DNS] 192.168.1.1:54321 <-> 8.8.8.8:53")
	}
}
