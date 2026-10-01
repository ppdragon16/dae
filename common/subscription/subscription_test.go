/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package subscription

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestResolveSubscriptionAsSIP008KeepsPlugin(t *testing.T) {
	sip := map[string]any{
		"version": 1,
		"servers": []map[string]any{
			{
				"remarks":     "obfs-node",
				"server":      "1.2.3.4",
				"server_port": 8388,
				"method":      "aes-128-gcm",
				"password":    "pw",
				"plugin":      "obfs-local",
				"plugin_opts": "obfs=http;obfs-host=example.com",
			},
			{
				"remarks":     "plain-node",
				"server":      "5.6.7.8",
				"server_port": 8388,
				"method":      "aes-128-gcm",
				"password":    "pw2",
			},
		},
	}
	b, err := json.Marshal(sip)
	if err != nil {
		t.Fatalf("marshal fixture: %v", err)
	}

	nodes, err := ResolveSubscriptionAsSIP008(b)
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if len(nodes) != 2 {
		t.Fatalf("expected 2 nodes, got %d", len(nodes))
	}

	obfsNode := nodes[0]
	if !strings.Contains(obfsNode, "plugin=obfs-local") {
		t.Fatalf("plugin name missing from node %q", obfsNode)
	}
	if !strings.Contains(obfsNode, "obfs%3Dhttp") {
		t.Fatalf("plugin opts missing from node %q", obfsNode)
	}

	plainNode := nodes[1]
	if strings.Contains(plainNode, "plugin") {
		t.Fatalf("plugin-less node must not carry a plugin param: %q", plainNode)
	}
}

// TestResolveSubscriptionRejectsOversizeDownload pins the read cap. This fork
// read the whole body with io.ReadAll, so an oversized (or hostile)
// subscription was buffered without bound; the cap must fail at the read with
// an error naming the limit instead of surfacing later as "resolved to 0 nodes".
func TestResolveSubscriptionRejectsOversizeDownload(t *testing.T) {
	old := maxSubscriptionSize
	maxSubscriptionSize = 1 << 10
	t.Cleanup(func() { maxSubscriptionSize = old })

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(bytes.Repeat([]byte("A"), int(maxSubscriptionSize)+1))
	}))
	defer srv.Close()

	_, _, err := ResolveSubscription(srv.Client(), t.TempDir(), srv.URL)
	if err == nil {
		t.Fatal("expected an oversize error")
	}
	if !strings.Contains(err.Error(), "exceeds the") || !strings.Contains(err.Error(), "byte limit") {
		t.Fatalf("err = %v, want it to name the limit", err)
	}
}

// TestResolveSubscriptionKeepsNormalDownloads covers the happy path the cap must
// not disturb: a small base64 subscription still resolves to its nodes.
func TestResolveSubscriptionKeepsNormalDownloads(t *testing.T) {
	const link = "socks5://127.0.0.1:1080"
	payload := base64.StdEncoding.EncodeToString([]byte(link + "\n"))

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(payload))
	}))
	defer srv.Close()

	_, nodes, err := ResolveSubscription(srv.Client(), t.TempDir(), srv.URL)
	if err != nil {
		t.Fatalf("ResolveSubscription: %v", err)
	}
	if len(nodes) != 1 || nodes[0] != link {
		t.Fatalf("nodes = %v, want [%s]", nodes, link)
	}
}

// TestResolveFileRejectsOversizeFile covers the same bound on the file branch
// (and on the persisted-cache read that goes through it).
func TestResolveFileRejectsOversizeFile(t *testing.T) {
	old := maxSubscriptionSize
	maxSubscriptionSize = 1 << 10
	t.Cleanup(func() { maxSubscriptionSize = old })

	dir := t.TempDir()
	subPath := filepath.Join(dir, "big.sub")
	// 0640: the file must not be group-writable or other-accessible.
	if err := os.WriteFile(subPath, bytes.Repeat([]byte("A"), int(maxSubscriptionSize)+1), 0640); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
	u := &url.URL{Scheme: "file", Host: ".", Path: "/big.sub"}

	_, err := ResolveFile(u, dir)
	if err == nil || !strings.Contains(err.Error(), "byte limit") {
		t.Fatalf("ResolveFile err = %v, want it to name the limit", err)
	}
}

// endlessReader never returns EOF, so reading it without a bound would consume
// memory until the process dies.
type endlessReader struct{}

func (endlessReader) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = 'A'
	}
	return len(p), nil
}

// TestReadAllCappedStopsAtTheLimit pins the memory-protection half of the cap,
// which a finite fixture cannot see: the read must stop at the limit even when
// the source never ends. Without io.LimitReader the body would be buffered
// whole before the length check ran.
func TestReadAllCappedStopsAtTheLimit(t *testing.T) {
	old := maxSubscriptionSize
	maxSubscriptionSize = 1 << 10
	t.Cleanup(func() { maxSubscriptionSize = old })

	done := make(chan error, 1)
	go func() {
		_, err := readAllCapped(endlessReader{}, "endless")
		done <- err
	}()
	select {
	case err := <-done:
		if err == nil || !strings.Contains(err.Error(), "byte limit") {
			t.Fatalf("err = %v, want it to name the limit", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("readAllCapped did not stop at the limit: the source is unbounded")
	}
}
