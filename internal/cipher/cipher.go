// Copyright (C) 2025 Michael J. Fromberger. All Rights Reserved.

// Package cipher implements symmetric encryption helpers for keyrings.
// The underlying cryptography is implemented by [chacha20poly1305].
package cipher

import (
	"crypto/pbkdf2"
	crand "crypto/rand"
	"crypto/sha3"
	"fmt"

	"golang.org/x/crypto/chacha20poly1305"
)

// KeyLen defines the key length in bytes of an encryption key.
const KeyLen = chacha20poly1305.KeySize

// GenerateKey generates a cryptographically random key of the specified length
// in bytes.
func GenerateKey(keyBytes int) []byte {
	pkey := make([]byte, keyBytes)
	crand.Read(pkey[:]) // panics on failure
	return pkey
}

// GenerateAndEncryptKey generates a cryptographically-random key of the
// specified length and encrypts it with the specified access key.
// The plaintext and ciphertext of the key are both returned.
func GenerateAndEncryptKey(accessKey []byte, n int) (plain, encrypted []byte, _ error) {
	pkey := GenerateKey(n)
	_, ekey, err := EncryptWithKey(accessKey, pkey, nil)
	if err != nil {
		return nil, nil, fmt.Errorf("encrypt key: %w", err)
	}
	return pkey, ekey, nil
}

// EncryptWithKey encrypts data using a [cipher.AEAD] over [chacha20poly1305]
// with the specified key and extra data. It returns the length of the AEAD
// nonce along with the encrypted result. The nonce occupies a prefix of the
// encrypted result.
func EncryptWithKey(key, data, extra []byte) (int, []byte, error) {
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return 0, nil, fmt.Errorf("initialize cipher: %w", err)
	}

	// Buffer layout:
	// [ <nonce> | <data> | <extra data> ]
	buf := make([]byte, aead.NonceSize(), aead.NonceSize()+len(data)+aead.Overhead())

	if _, err := crand.Read(buf); err != nil {
		return 0, nil, fmt.Errorf("generate nonce: %w", err)
	}
	return aead.NonceSize(), aead.Seal(buf, buf, data, extra), nil
}

// DecryptWithKey decrypts data using a [cipher.AEAD] over [chacha20poly1305]
// with the specified key and extra data.
func DecryptWithKey(key, data, extra []byte) ([]byte, error) {
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, fmt.Errorf("initialize cipher: %w", err)
	}
	if len(data) < aead.NonceSize() {
		return nil, fmt.Errorf("short nonce (%d < %d)", len(data), aead.NonceSize())
	}
	nonce, ctext := data[:aead.NonceSize()], data[aead.NonceSize():]
	return aead.Open(nil, nonce, ctext, extra)
}

// KeyFromPassphrase returns a cryptographic key of n byte, derived via
// [pbkdf2.Key] using the specified passphrase and a random salt.
// If salt == nil, a new random salt is generated and returned; otherwise
// the provided value is used in the KDF.
// The key and the salt are returned.
func KeyFromPassphrase(passphrase string, n int, salt []byte) (_key, _salt []byte) {
	if salt == nil {
		salt = make([]byte, 32)
		crand.Read(salt)
	}
	key, err := pbkdf2.Key(sha3.New256, passphrase, salt, 4096, n)
	if err != nil {
		// Can only happen if we violate FIPS key length or digest rules, both of
		// which should never happen with our usage patterns.
		panic(fmt.Sprintf("pbkdf2.Key failed: %v", err))
	}
	return key, salt
}
