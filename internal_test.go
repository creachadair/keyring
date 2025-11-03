// Copyright (C) 2025 Michael J. Fromberger. All Rights Reserved.

package keyring

import (
	"bytes"
	"testing"

	"github.com/creachadair/keyring/internal/cipher"
	"github.com/creachadair/keyring/internal/packet"
	"github.com/google/go-cmp/cmp"
)

func TestRoundTripInternal(t *testing.T) {
	accessKey := []byte("0123456-0123456-0123456-01234567")
	dataKey := []byte("98765432012345679876543201234567")
	_, dataKeyEncrypted, err := cipher.EncryptWithKey(accessKey, dataKey, nil)
	if err != nil {
		t.Fatalf("Encrypt data key: %v", err)
	}

	afunc := func(salt []byte) []byte {
		if got := string(salt); got != "salt" {
			t.Errorf("Salt: got %q, want salt", got)
		}
		return accessKey
	}

	r := &Ring{
		formatVersion: 1,
		accessKeySalt: []byte("salt"),
		dkEncrypted:   dataKeyEncrypted,
		dkPlaintext:   dataKey,

		view: View{
			keys: []packet.KeyInfo{
				{ID: 1, Key: []byte("minsc")},
				{ID: 2, Key: []byte("boo")},
				{ID: 3, Key: []byte("dynaheir")},
			},
			activeKey: 1,
		},
		maxID: 3,
	}

	var buf bytes.Buffer
	nw, err := r.WriteTo(&buf)
	if err != nil {
		t.Fatalf("WriteTo failed: %v", err)
	}
	t.Logf("Wrote %d bytes", nw)

	s, err := Read(bytes.NewReader(buf.Bytes()), afunc)
	if err != nil {
		t.Fatalf("Read failed: %v", err)
	}

	if diff := cmp.Diff(s, r, cmp.AllowUnexported(Ring{}, View{})); diff != "" {
		t.Errorf("Round trip (-got, +want):\n%s", diff)
	}
}
