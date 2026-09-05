/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package quicutils

import (
	"bytes"
	"encoding/hex"
	"testing"

	"github.com/daeuniverse/dae/common"
	"github.com/daeuniverse/outbound/pool"
)

var destConnId = []byte{0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08}

func TestDeriveKeys(t *testing.T) {
	// https://datatracker.ietf.org/doc/html/rfc9001#name-keys
	keys, err := NewKeys(destConnId, Version_V1, common.NewGcm)
	if err != nil {
		t.Fatal(err)
	}
	defer keys.Close()

	t.Logf("%#v", keys)
	clientInitialSecret, _ := hex.DecodeString("c00cf151ca5be075ed0ebfb5c80323c42d6b7db67881289af4008f1f6c357aea")
	if !bytes.Equal(keys.clientInitialSecret, clientInitialSecret) {
		t.Fatal("key")
	}
	key, _ := hex.DecodeString("1f369613dd76d5467730efcbe3b1a22d")
	if !bytes.Equal(keys.key, key) {
		t.Fatal("key")
	}
	iv, _ := hex.DecodeString("fa044b2f42a3fd3b46fb255c")
	if !bytes.Equal(keys.iv, iv) {
		t.Fatal("iv")
	}
	hp, _ := hex.DecodeString("9f50449e04a0e810283a1e9933adedd2")
	if !bytes.Equal(keys.headerProtectionKey, hp) {
		t.Fatal("hp")
	}
}

func TestKeys_HeaderProtection_(t *testing.T) {
	// https://datatracker.ietf.org/doc/html/rfc9001#name-client-initial
	keys, err := NewKeys(destConnId, Version_V1, common.NewGcm)
	if err != nil {
		t.Fatal("NewKeys", err)
	}
	defer keys.Close()

	sample, _ := hex.DecodeString("d1b1c98dd7689fb8ec11d242b123dc9b")
	flag := byte(0xc3)
	packetNumber, _ := hex.DecodeString("00000002")
	if packetNumber, err = keys.HeaderProtection_(sample, true, &flag, packetNumber); err != nil {
		t.Fatal("HeaderProtection_", err)
	}
	if flag != 0xc0 {
		t.Fatal("flag:", flag)
	}
	if !bytes.Equal(packetNumber, []byte{0x7b}) {
		t.Fatalf("packetNumber: %x", packetNumber)
	}
}

func TestKeys_PayloadDecrypt_(t *testing.T) {
	destConnId, _ := hex.DecodeString("7f9863b69d513af6a050f0272dfe4dd1")
	keys, err := NewKeys(destConnId, Version_Draft, common.NewGcm)
	if err != nil {
		t.Fatal("NewKeys", err)
	}
	defer keys.Close()

	data, _ := hex.DecodeString("cfff00001d107f9863b69d513af6a050f0272dfe4dd114cb9b88815f5c3e385f2a8756c2a76c61fe0a6ddf0041222cce1ec1f09bb7d134541f214437ebaac82ad3044e24abffb166407f6e8e41584fe9717fbec115d345c934408aa9314bb9e8a3487ea2c17a7ff02f65d3ed8f76a462034260bb41d6ef8f0fa78d6920074a10091f85d322c10f1f4eb7e207c2283c4df5857edea1279248ba03ba83c4727b759f564dcd4db3e6e11d40abce3d4362caf5ef592a3cde2d66acadc7428b5cccf28eb1461b0c3ca595ff7425f5898b95bf4917786a5f9ce7226dd0be61cff453bd74decfa057d3afaef136226e9ba23ad3e28da820a367b4788786efa97bf59033b87bc8a4555b86148cfde85ea16772eb1d81e14c9056f3f36a4f789bc608145712fa7cd28f93e76d3f90e80815e267aeefff2bc44299f8b65e3cf99816c96f33723d20565162cc843024bdbd83a90d2f")
	header := data[:50]
	potentialPacketNumber := header[len(header)-4:]
	sample := data[50 : 50+16]
	flag := &header[0]
	var packetNumber []byte
	if packetNumber, err = keys.HeaderProtection_(sample, true, flag, potentialPacketNumber); err != nil {
		t.Fatal("HeaderProtection_", err)
	}
	if *flag != 0b11000000 {
		t.Fatalf("flag: %b", *flag)
	}
	if !bytes.Equal(packetNumber, []byte{1}) {
		t.Fatal("packetNumber:", packetNumber)
	}
	header = data[:len(header)-4+len(packetNumber)]
	payload := data[len(header):]
	plaintext, err := keys.PayloadDecrypt(payload, packetNumber, header)
	if err != nil {
		t.Fatal("PayloadDecryptFromPool:", err)
	}
	t.Log(hex.EncodeToString(plaintext))
}

// TestKeys_PayloadDecrypt_RecyclesBufferOnAuthFailure verifies that an AEAD
// authentication failure still returns the pooled plaintext buffer to the
// pool (bogus QUIC-looking packets hit this path constantly).
func TestKeys_PayloadDecrypt_RecyclesBufferOnAuthFailure(t *testing.T) {
	keys, err := NewKeys(destConnId, Version_V1, common.NewGcm)
	if err != nil {
		t.Fatal("NewKeys", err)
	}
	defer keys.Close()

	// plaintext length 300 → GetBuffer serves size class 512 (stats index 9).
	const classIdx = 9
	ciphertext := make([]byte, 300+16) // + AEAD overhead
	header := []byte{0xc3, 0x00, 0x00, 0x00, 0x01}
	packetNumber := []byte{0x02}

	var stats pool.StatsSnapshot
	pool.PoolStats(&stats)
	putsBefore := stats[classIdx].Puts

	if _, err = keys.PayloadDecrypt(ciphertext, packetNumber, header); err == nil {
		t.Fatal("expected authentication failure for garbage ciphertext")
	}

	pool.PoolStats(&stats)
	if got := stats[classIdx].Puts - putsBefore; got != 1 {
		t.Fatalf("expected exactly 1 PutBuffer into class %d after auth failure, got %d", 1<<classIdx, got)
	}
}

// TestKeys_Close_ScrubsAndPools verifies that Close zeroes the derived key
// material (three of the four key buffers are handed to the shared pool) and
// pools exactly the pow2-cap buffers: 32-class once (clientInitialSecret),
// 16-class twice (key, headerProtectionKey); iv (cap 12) must not be pooled.
func TestKeys_Close_ScrubsAndPools(t *testing.T) {
	keys, err := NewKeys(destConnId, Version_V1, common.NewGcm)
	if err != nil {
		t.Fatal("NewKeys", err)
	}

	var stats pool.StatsSnapshot
	pool.PoolStats(&stats)
	puts32 := stats[5].Puts // class 32
	puts16 := stats[4].Puts // class 16

	if err = keys.Close(); err != nil {
		t.Fatal("Close", err)
	}

	for name, buf := range map[string][]byte{
		"clientInitialSecret": keys.clientInitialSecret,
		"key":                 keys.key,
		"iv":                  keys.iv,
		"headerProtectionKey": keys.headerProtectionKey,
		"nonce":               keys.nonce,
	} {
		for i, b := range buf {
			if b != 0 {
				t.Fatalf("%s not scrubbed: byte %d = %#x", name, i, b)
			}
		}
	}

	pool.PoolStats(&stats)
	if got := stats[5].Puts - puts32; got != 1 {
		t.Fatalf("expected exactly 1 PutBuffer into class 32, got %d", got)
	}
	if got := stats[4].Puts - puts16; got != 2 {
		t.Fatalf("expected exactly 2 PutBuffers into class 16, got %d", got)
	}
}
