package keyring_test

import (
	"bytes"
	crand "crypto/rand"
	"io"
	mrand "math/rand/v2"
	"strings"
	"sync"
	"testing"

	"github.com/creachadair/keyring"
	"github.com/creachadair/mds/mtest"
	"github.com/google/go-cmp/cmp"
)

var rng = sync.OnceValue(func() io.Reader {
	var seed [32]byte
	crand.Read(seed[:]) // panics on error
	return mrand.NewChaCha8(seed)
})

func randomBytes(n int) []byte {
	buf := make([]byte, n)
	rng().Read(buf)
	return buf
}

func checkError(t *testing.T, label string, err error, text string) {
	t.Helper()
	if err == nil {
		t.Fatalf("%s: unexpectedly succeeded", label)
	} else if !strings.Contains(err.Error(), text) {
		t.Errorf("%s: got error %v, want %s", label, err, text)
	}
}

func checkHasKeys(t *testing.T, r *keyring.Ring, ids ...keyring.ID) {
	t.Helper()
	for _, id := range ids {
		if !r.Has(id) {
			t.Errorf("missing key for id %v", id)
		}
	}
	if n := r.Len(); n != len(ids) {
		t.Errorf("keyring has %d keys, want %d", n, len(ids))
	}
}

func TestBasic(t *testing.T) {
	accessKey := make([]byte, keyring.AccessKeyLen)
	const firstKey = "hunter2"
	const secondKey = "hunter2hunter2"

	r, err := keyring.New(keyring.Config{
		InitialKey: []byte(firstKey),
		AccessKey:  accessKey,
	})
	if err != nil {
		t.Fatalf("New failed: %v", err)
	}
	if n := r.Len(); n != 1 {
		t.Errorf("Len: got %d, want 1", n)
	}
	if id := r.Active(); id != 1 {
		t.Errorf("Active: got %v, want 1", id)
	}
	if got := string(r.Get(keyring.ActiveKey)); got != firstKey {
		t.Errorf("Active key: got %q, want %q", got, firstKey)
	}

	// Add a new key...
	id2 := r.Add([]byte(secondKey))

	// The new key should not be active yet.
	if got := string(r.Get(keyring.ActiveKey)); got != firstKey {
		t.Errorf("Active key: got %q, want %q", got, firstKey)
	}

	r.Activate(id2)

	if id := r.Active(); id != id2 {
		t.Errorf("Active: got %v, want %v", id, id2)
	}
	if got := string(r.Get(keyring.ActiveKey)); got != secondKey {
		t.Errorf("Active key: got %q, want %q", got, secondKey)
	}

	// Check the list of available IDs.
	checkHasKeys(t, r, 1, 2)
}

func TestRoundTrip(t *testing.T) {
	accessKey := make([]byte, keyring.AccessKeyLen)
	const testSalt = "everything tastes better with salt"
	const firstKey = "1234"
	testKeys := []string{firstKey, "secret", "hunter2", "one1111!", "admin123"}

	r, err := keyring.New(keyring.Config{
		InitialKey:    []byte(firstKey),
		AccessKey:     accessKey,
		AccessKeySalt: []byte(testSalt),
	})
	if err != nil {
		t.Fatalf("New failed: %v", err)
	}
	wantID := []keyring.ID{r.Active()}
	for _, key := range testKeys[1:] {
		wantID = append(wantID, r.Add([]byte(key)))
	}

	// Verify basic properties.
	checkHasKeys(t, r, wantID...)
	if id := r.Active(); id != 1 {
		t.Errorf("Active: got %d, want 1", id)
	}
	if got := string(r.Get(r.Active())); got != firstKey {
		t.Errorf("Active key: got %q, want %q", got, firstKey)
	}

	r.Activate(2)

	// Encode the keyring in binary format.
	var buf bytes.Buffer
	nw, err := r.WriteTo(&buf)
	if err != nil {
		t.Fatalf("WriteTo failed: %v", err)
	}
	t.Logf("Encoded keyring as %d bytes", nw)

	// Load the binary encoding back and check its contents.
	r2, err := keyring.Read(&buf, func(salt []byte) []byte {
		if got := string(salt); got != testSalt {
			t.Errorf("Read: salt is %q, want %q", got, testSalt)
		}
		return accessKey
	})
	if err != nil {
		t.Fatalf("Read failed: %v", err)
	}

	// The list of key IDs.
	checkHasKeys(t, r, 1, 2, 3, 4, 5)
	checkHasKeys(t, r2, 1, 2, 3, 4, 5)

	// The contents of the keys, in ID order.

	var gotKeys []string
	for id := range 5 {
		gotKeys = append(gotKeys, string(r2.Get(keyring.ID(id+1))))
	}
	if diff := cmp.Diff(gotKeys, testKeys); diff != "" {
		t.Errorf("Decoded keys (-got, +want):\n%s", diff)
	}

	// The active key version.
	if got, want := r2.Active(), r.Active(); got != want {
		t.Errorf("Decoded active: got %v, want %v", got, want)
	}
}

func TestErrors(t *testing.T) {
	accessKey := make([]byte, keyring.AccessKeyLen)
	r, err := keyring.New(keyring.Config{
		AccessKey:  accessKey,
		InitialKey: []byte("ok I am awake"),
	})
	if err != nil {
		t.Fatalf("New failed: %v", err)
	}

	t.Run("AccessKeyLen", func(t *testing.T) {
		_, err := keyring.New(keyring.Config{AccessKey: []byte("wrong length"), InitialKey: []byte("ok")})
		checkError(t, "New", err, "access key is 12 bytes, want 32")
	})

	t.Run("NoInitialKey", func(t *testing.T) {
		_, err := keyring.New(keyring.Config{AccessKey: accessKey})
		checkError(t, "New", err, "initial key is empty")
	})

	t.Run("NoAccessKey", func(t *testing.T) {
		_, err := keyring.New(keyring.Config{InitialKey: []byte("ok")})
		checkError(t, "New", err, "access key is 0 bytes")
	})

	t.Run("ActivateMissing", func(t *testing.T) {
		mtest.MustPanic(t, func() { r.Activate(0) })
		mtest.MustPanic(t, func() { r.Activate(12345) })
	})

	t.Run("GetMissing", func(t *testing.T) {
		mtest.MustPanic(t, func() { r.Get(12345) })
	})

	t.Run("AppendMissing", func(t *testing.T) {
		mtest.MustPanic(t, func() { r.Append(12345, nil) })
	})

	t.Run("AddEmpty", func(t *testing.T) {
		mtest.MustPanic(t, func() { r.Add(nil) })
		mtest.MustPanic(t, func() { r.Add([]byte{}) })
	})

	t.Run("AddBadRandom", func(t *testing.T) {
		mtest.MustPanic(t, func() { r.AddRandom(0) })
		mtest.MustPanic(t, func() { r.AddRandom(-1) })
	})
}

func TestRekey(t *testing.T) {
	const testKey = "asha athena and zuul"

	accessKey1 := randomBytes(keyring.AccessKeyLen)
	r, err := keyring.New(keyring.Config{
		AccessKey:  accessKey1,
		InitialKey: []byte(testKey),
	})
	if err != nil {
		t.Fatalf("New failed: %v", err)
	}

	// Write the version protected by accessKey1.
	var buf1 bytes.Buffer
	if _, err := r.WriteTo(&buf1); err != nil {
		t.Fatalf("Write keyring: %v", err)
	}
	k1 := bytes.NewReader(buf1.Bytes())

	accessKey2 := randomBytes(keyring.AccessKeyLen)
	if err := r.Rekey(accessKey2, []byte("acorn")); err != nil {
		t.Fatalf("Rekey failed: %v", err)
	}

	// Write the version protected by accessKey2.
	var buf2 bytes.Buffer
	if _, err := r.WriteTo(&buf2); err != nil {
		t.Fatalf("Write keyring: %v", err)
	}
	k2 := bytes.NewReader(buf2.Bytes())

	// Reading buf1 with k1 should work.
	if r2, err := keyring.Read(k1, keyring.StaticKey(accessKey1)); err != nil {
		t.Fatalf("Read k1 failed: %v", err)
	} else if got := string(r2.Get(keyring.ActiveKey)); got != testKey {
		t.Errorf("k1 active: got %q, want %q", got, testKey)
	}

	// Reading buf1 with k2 should fail.
	k1.Seek(0, io.SeekStart)
	if r2, err := keyring.Read(k1, keyring.StaticKey(accessKey2)); err == nil {
		t.Errorf("Read k1: got %v, want error", r2)
	}

	// Reading buf2 with k1 should fail.
	if r2, err := keyring.Read(k2, keyring.StaticKey(accessKey1)); err == nil {
		t.Errorf("Read k2: got %v, want error", r2)
	}

	// Reading buf2 with k2 should work.
	k2.Seek(0, io.SeekStart)
	if r2, err := keyring.Read(k2, func(salt []byte) []byte {
		// Check that we kept the salt set during rekeying.
		if got := string(salt); got != "acorn" {
			t.Errorf("Wrong salt: got %q, want acorn", got)
		}
		return accessKey2
	}); err != nil {
		t.Fatalf("Read k2 failed: %v", err)
	} else if got := string(r2.Get(r2.Active())); got != testKey {
		t.Errorf("k2 active: got %q, want %q", got, testKey)
	}
}

func TestHKDF(t *testing.T) {
	const passphrase = "character is what you are in the dark"

	// Derive a key from passphrase with HKDF, and use it to create a keyring.
	key, salt := keyring.AccessKeyFromPassphrase(passphrase)
	r, err := keyring.New(keyring.Config{
		AccessKey:     key,
		AccessKeySalt: salt,
		InitialKey:    []byte("hunter2"),
	})
	if err != nil {
		t.Fatalf("New failed: %v", err)
	}

	var buf bytes.Buffer
	if _, err := r.WriteTo(&buf); err != nil {
		t.Fatalf("Write keyring failed: %v", err)
	}

	// Verify that the HKDF access key function works to re-open the keyring.
	r2, err := keyring.Read(&buf, keyring.HKDF(passphrase))
	if err != nil {
		t.Fatalf("Read failed: %v", err)
	}

	got := string(r2.Get(r2.Active()))
	want := string(r2.Get(r2.Active()))
	if got != want {
		t.Errorf("Got key %q, want %q", got, want)
	}
}

func TestNoSharing(t *testing.T) {
	var zero [keyring.AccessKeyLen]byte
	const testKey = "apple pear plum cherry"
	testKeyBytes := []byte(testKey)
	r, err := keyring.New(keyring.Config{
		AccessKey:  zero[:],
		InitialKey: testKeyBytes,
	})
	if err != nil {
		t.Fatalf("New failed: %v", err)
	}

	// Editing the bytes we put in does not affect the stored copy.
	clear(testKeyBytes)
	if got := r.Append(0, nil); string(got) != testKey {
		t.Errorf("Stored key modified: got %q, want %q", got, testKey)
	}

	// Editing the results from Get does not affect the stored copy.
	key := r.Get(0)
	clear(key)
	if got := r.Append(0, nil); string(got) != testKey {
		t.Errorf("Stored key modified: got %q, want %q", got, testKey)
	}

	testKeyBytes = r.Append(0, testKeyBytes[:0])
	if string(testKeyBytes) != testKey {
		t.Errorf("Append: got %q, want %q", testKeyBytes, testKey)
	}
}
