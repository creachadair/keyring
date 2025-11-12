// Copyright (C) 2025 Michael J. Fromberger. All Rights Reserved.

package keyring_test

import (
	"bytes"
	"fmt"
	"log"

	"github.com/creachadair/keyring"
)

func Example() {
	key, salt := keyring.AccessKeyFromPassphrase("hunter2")

	r, err := keyring.New(keyring.Config{
		AccessKey:     key,
		AccessKeySalt: salt,
		InitialKey:    []byte("too many secrets"),
	})
	if err != nil {
		log.Fatalf("New failed: %v", err)
	}

	// Print the currently-active key.
	fmt.Printf("Key %d: %q\n", r.Active(), r.Get(r.Active(), nil))

	// Add another key and print that too.
	id := r.Add([]byte("no more secrets"))
	fmt.Printf("Key %d: %q\n", id, r.Get(id, nil))

	// Note that the active key ID doesn't change until we say so.
	fmt.Printf("Active ID before: %d\n", r.Active())
	r.Activate(id)
	fmt.Printf("Active ID after: %d\n", r.Active())

	var buf bytes.Buffer
	nw, err := r.WriteTo(&buf)
	if err != nil {
		log.Fatalf("Write failed: %v", err)
	}
	fmt.Printf("Encoded keyring is %d bytes\n\n", nw)

	// Read the keyring back in from "storage" (buf).
	r2, err := keyring.Read(&buf, keyring.PassphraseKey("hunter2"))
	if err != nil {
		log.Fatalf("Read failed: %v", err)
	}
	fmt.Println("(reloaded)")
	id, akey := r2.GetActive(nil)
	fmt.Printf("Key %d: %q\n", id, akey)

	// Output:
	// Key 1: "too many secrets"
	// Key 2: "no more secrets"
	// Active ID before: 1
	// Active ID after: 2
	// Encoded keyring is 199 bytes
	//
	// (reloaded)
	// Key 2: "no more secrets"
}
