// Copyright (C) 2025 Michael J. Fromberger. All Rights Reserved.

package keyring

import (
	"fmt"

	"github.com/creachadair/keyring/internal/packet"
)

// A View is a read-only view of a [Ring]. Keys cannot be added to a view, the
// active key ID cannot be changed, and it cannot be written to storage.
type View struct {
	keys      []packet.KeyInfo
	activeKey int
}

// View returns a read-only view of r.
func (r *Ring) View() *View {
	cp := make([]packet.KeyInfo, len(r.keys))
	for i, ki := range r.keys {
		cp[i] = ki.Clone()
	}
	return &View{keys: cp, activeKey: r.activeKey}
}

// Len reports the number of keys in v.
func (v *View) Len() int { return len(v.keys) }

// Active reports the current active key ID in v.
func (v *View) Active() ID { return v.keys[v.activeKey].ID }

// Has reports whether v contains a key with the given ID.
func (v *View) Has(id ID) bool { return packet.FindKey(v.keys, id) >= 0 }

// Append appends the contents of the specified key to buf, and returns the
// resulting slice. It panics if id does not exist in r.
func (v *View) Append(id ID, buf []byte) []byte {
	pos := packet.FindKey(v.keys, id)
	if pos < 0 {
		panic(fmt.Sprintf("keyring: no such key: %v", id))
	}
	return append(buf, v.keys[pos].Key...)
}

// AppendActive appends the contents of the active key to buf, and returns
// active ID and the updated slice.
func (v *View) AppendActive(buf []byte) (ID, []byte) {
	ki := v.keys[v.activeKey]
	return ki.ID, append(buf, ki.Key...)
}

// Get returns a copy of the specified key. It will panic if id does not exist
// in v.  Get is equivalent to [Ring.Append] with an empty slice.
func (v *View) Get(id ID) []byte { return v.Append(id, nil) }

// GetActive returns the ID and a copy of the current active key.
// It is equivalent to [Ring.AppendActive] with an empty slice.
func (v *View) GetActive() (ID, []byte) { return v.AppendActive(nil) }
