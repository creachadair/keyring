// Package cipher implements symmetric encryption helpers for keyrings.
// The underlying cryptography is implemented by [chacha20poly1305].
package cipher

import (
	crand "crypto/rand"
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
