/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package subscription

import (
	"encoding/json"
	"strings"
	"testing"
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
