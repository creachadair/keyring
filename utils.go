package keyring

import (
	"runtime"

	"github.com/creachadair/keyring/internal/cipher"
	"github.com/creachadair/keyring/internal/packet"
)

// addCleanup adds cleanup handlers to make a best effort to zero out
// unencrypted key material in r when r is reclaimed by the GC.
func addCleanup(r *Ring) *Ring {
	runtime.AddCleanup(r, func(keys []packet.KeyInfo) {
		for _, ki := range keys {
			clear(ki.Key)
		}
	}, r.keys)
	runtime.AddCleanup(r, func(key []byte) { clear(key) }, r.dkPlaintext)
	return r
}

func (r *Ring) addBytes(data []byte) ID {
	r.maxID++
	pos := len(r.keys)
	r.keys = append(r.keys, packet.KeyInfo{
		ID:  int(r.maxID),
		Key: data,
	})
	return ID(r.keys[pos].ID)
}

// AccessKeyLen is the length in bytes of an access key.
const AccessKeyLen = cipher.KeyLen // 32 bytes

// AccessKeyFunc is a function that generates an access key from a generation
// salt. The implementation is not required to use the salt. It must return a
// slice of exactly [AccessKeyLen] bytes.
type AccessKeyFunc func([]byte) []byte

// StaticKey returns an access key generation function that ignores the key
// generation salt and returns the provided key.
func StaticKey(key []byte) AccessKeyFunc { return func([]byte) []byte { return key } }

// PassphraseKey returns an access key generation function generates an access
// key using PBKDF2 on the provided passphrase and the stored salt.
func PassphraseKey(passphrase string) AccessKeyFunc {
	return func(salt []byte) []byte {
		key, _ := cipher.KeyFromPassphrase(passphrase, AccessKeyLen, salt)
		return key
	}
}

// AccessKeyFromPassphrase generates a key from the specified passphrase using
// PBKDF2 and a random salt. It returns the key and the salt.
func AccessKeyFromPassphrase(passphrase string) (key, salt []byte) {
	return cipher.KeyFromPassphrase(passphrase, AccessKeyLen, nil)
}
