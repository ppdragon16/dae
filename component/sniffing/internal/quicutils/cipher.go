/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package quicutils

import (
	"bytes"
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"io"

	"github.com/daeuniverse/outbound/pool"
	utls "github.com/refraction-networking/utls"
)

const (
	MaxVarintLen64 = 8

	MaxPacketNumberLength = 4
	SampleSize            = 16
)

var (
	InitialClientLabel = "client in"
)

type Keys struct {
	version             Version
	dcid                []byte
	clientInitialSecret []byte
	key                 []byte
	iv                  []byte
	headerProtectionKey []byte
	newAead             func(key []byte) (cipher.AEAD, error)
	aead                cipher.AEAD
	block               cipher.Block
	nonce               []byte
}

func (k *Keys) Close() error {
	pool.PutBuffer(k.clientInitialSecret)
	pool.PutBuffer(k.headerProtectionKey)
	pool.PutBuffer(k.iv)
	pool.PutBuffer(k.key)
	return nil
}

func NewKeys(clientDstConnectionId []byte, version Version, newAead func(key []byte) (cipher.AEAD, error)) (keys *Keys, err error) {
	// https://datatracker.ietf.org/doc/html/rfc9001#name-keys
	initialSecret := utls.HKDFExtract(crypto.SHA256, clientDstConnectionId, version.InitialSalt())
	clientInitialSecret := utls.HKDFExpandLabel(crypto.SHA256, initialSecret, InitialClientLabel, nil, 32)

	keys = &Keys{
		clientInitialSecret: clientInitialSecret,
		version:             version,
		newAead:             newAead,
		dcid:                append([]byte(nil), clientDstConnectionId...),
	}
	// We differentiated a deriveKeys func is just for example test.
	if err = keys.deriveKeys(); err != nil {
		keys.Close()
		return nil, err
	}

	return keys, nil
}

func (k *Keys) deriveKeys() (err error) {
	k.key = utls.HKDFExpandLabel(crypto.SHA256, k.clientInitialSecret, string(k.version.KeyLabel()), nil, 16)
	k.iv = utls.HKDFExpandLabel(crypto.SHA256, k.clientInitialSecret, string(k.version.IvLabel()), nil, 12)
	k.headerProtectionKey = utls.HKDFExpandLabel(crypto.SHA256, k.clientInitialSecret, string(k.version.HpLabel()), nil, 16)
	// Derive the cipher objects once, so repeated Initial packets of the same
	// connection reuse them instead of rebuilding AES/GCM per packet.
	if k.aead, err = k.newAead(k.key); err != nil {
		return err
	}
	k.nonce = make([]byte, len(k.iv))
	if k.block, err = aes.NewCipher(k.headerProtectionKey); err != nil {
		return err
	}
	return nil
}

// Matches reports whether k was derived for the given destination connection
// id and QUIC version.
func (k *Keys) Matches(destConnId []byte, version Version) bool {
	return k != nil && k.version == version && bytes.Equal(k.dcid, destConnId)
}

// HeaderProtection_ encrypt/decrypt firstByte and packetNumber in place.
func (k *Keys) HeaderProtection_(sample []byte, longHeader bool, firstByte *byte, potentialPacketNumber []byte) (packetNumber []byte, err error) {
	block := k.block
	// Get mask.
	mask := pool.GetBuffer(block.BlockSize())
	defer pool.PutBuffer(mask)
	block.Encrypt(mask, sample)
	// Encrypt/decrypt first byte.
	if longHeader {
		// Long header: 4 bits masked
		// High 4 bits are not protected.
		*firstByte ^= mask[0] & 0x0f
	} else {
		// Short header: 5 bits masked
		// High 3 bits are not protected.
		*firstByte ^= mask[0] & 0x1f
	}
	// The length of the Packet Number field is the value of this field plus one.
	packetNumberLength := int((*firstByte & 0b11) + 1)
	packetNumber = potentialPacketNumber[:packetNumberLength]

	// Encrypt/decrypt packet number.
	for i := range packetNumber {
		packetNumber[i] ^= mask[1+i]
	}
	return packetNumber, nil
}

func (k *Keys) PayloadDecrypt(ciphertext []byte, packetNumber []byte, header []byte) (plaintext []byte, err error) {
	// https://datatracker.ietf.org/doc/html/rfc9001#name-initial-secrets

	// Build the per-packet nonce (IV XOR packet number) in a scratch buffer
	// instead of mutating k.iv in place, so the cached keys stay reusable
	// across repeated Initial packets of the same connection.
	copy(k.nonce, k.iv)
	for i := range packetNumber {
		k.nonce[len(k.nonce)-len(packetNumber)+i] ^= packetNumber[i]
	}
	plaintext = make([]byte, len(ciphertext)-k.aead.Overhead())
	plaintext, err = k.aead.Open(plaintext[:0], k.nonce, ciphertext, header)
	if err != nil {
		return nil, err
	}
	return plaintext, nil
}

func DecryptQuic_(keys *Keys, header []byte, blockEnd int) (plaintext []byte, err error) {
	if blockEnd-len(header) < SampleSize {
		return nil, io.ErrUnexpectedEOF
	}
	// Sample 16B
	sample := header[len(header) : len(header)+SampleSize]

	// Decrypt header flag and packet number.
	var packetNumber []byte
	if packetNumber, err = keys.HeaderProtection_(sample, true, &header[0], header[len(header)-MaxPacketNumberLength:]); err != nil {
		return nil, err
	}
	header = header[:len(header)-MaxPacketNumberLength+len(packetNumber)] // Correct header
	payload := header[len(header):blockEnd]                               // Correct payload

	plaintext, err = keys.PayloadDecrypt(payload, packetNumber, header)
	if err != nil {
		return nil, err
	}

	return plaintext, nil
}
