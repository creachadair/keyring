package keyring

import (
	"crypto/hkdf"
	crand "crypto/rand"
	"crypto/sha3"
	"fmt"
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

// HKDF returns an access key generation function generates an access key using
// the [hkdf.Key] function with [sha3.SHA3] from the provided passphrase.
func HKDF(passphrase string) AccessKeyFunc {
	return func(salt []byte) []byte {
		// It should not be possible for this to fail; the only error conditions
		// are a non-FIPS hash in a FIPS context (SHA3 is FIPS compliant), or a
		// key length that exceeds 255 times the hash size (which this does not).
		key, err := hkdf.Key(sha3.New256, []byte(passphrase), salt, "", AccessKeyLen)
		if err != nil {
			panic(fmt.Sprintf("hkdf failed: %v", err))
		}
		return key
	}
}

// AccessKeyFromPassphrase generates a key from the specified passphrase using
// [hkdf.Key] with [sha3.SHA3] and a random salt. It returns the key and the salt.
func AccessKeyFromPassphrase(passphrase string) (key, salt []byte) {
	salt = make([]byte, 32)
	crand.Read(salt) // panics on failure
	key, err := hkdf.Key(sha3.New256, []byte(passphrase), salt, "", AccessKeyLen)
	if err != nil {
		panic(fmt.Sprintf("hkdf failed: %v", err))
	}
	return key, salt
}
