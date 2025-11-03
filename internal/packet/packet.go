// Copyright (C) 2025 Michael J. Fromberger. All Rights Reserved.

// Packet packet defines the binary storage representation of a
// keyring as defined by the parent package.
//
// Keyring binary format
//
//	Pos   | Size    | Description
//	------|---------|--------------------------------------------------
//	0     | 2       | Magic number [0xec 0x01]; 0x01 is format version
//	2     | 2       | Reserved [0x00 0x00]; must be zero in format 1
//	4     | (rest)  | * packet (see below)
//
// The only understood format version is 0x01.
//
// Packet format
//
//	Pos   | Size    | Description
//	------|---------|--------------------------------------------------
//	0     | 1       | Packet type (see below)
//	1     | 3       | Packet content length (BE uint24) = n
//	4     | n       | Packet content
//
// Packet types
//
//	 Code | Meaning           | Format
//	------|-------------------|-----------------------------------
//	 0, 1 | (reserved)        | (not used)
//	 2    | data storage key  | cipher packet
//	 3    | access key salt   | bytes
//	 4    | keyring entry     | bytes
//	 5    | active key ID     | [4]byte (BE uint32)
//	 6    | encrypted bundle  | cipher packet
//
// All types not listed here are reserved.
//
// Cipher packet format
//
//	Pos   | Size    | Description
//	------|---------|--------------------------------------------------
//	0     | 24      | encryption nonce
//	24    | (rest)  | AEAD sealed content
//
// A bundle packet is a cipher packet whose AEAD sealed content is itself a
// sequence of packets, encrypted with the data encryption key.  This package
// encrypts using an AEAD over chacha20poly1305 with a 24-byte nonce.
package packet

import (
	"bytes"
	"cmp"
	"encoding/binary"
	"errors"
	"fmt"
	"slices"

	"github.com/creachadair/keyring/internal/cipher"
)

// KeyInfo is the parsed representation of a stored key.
type KeyInfo struct {
	ID  int
	Key []byte
}

func (ki KeyInfo) compareID(id int) int  { return cmp.Compare(ki.ID, id) }
func (ki KeyInfo) compare(o KeyInfo) int { return cmp.Compare(ki.ID, o.ID) }

// Clone returns a deep clone of ki.
func (ki KeyInfo) Clone() KeyInfo { return KeyInfo{ID: ki.ID, Key: bytes.Clone(ki.Key)} }

// FindKey reports the location of the specified id in keys, or -1.
// Precondition: keys is sorted increasing by id.
func FindKey(keys []KeyInfo, id int) int {
	pos, ok := slices.BinarySearchFunc(keys, id, KeyInfo.compareID)
	if ok {
		return pos
	}
	return -1
}

// SortKeysByID sorts keys in-place by ID.
func SortKeysByID(keys []KeyInfo) { slices.SortFunc(keys, KeyInfo.compare) }

// ParseKeyInfo parses the binary encoding of a [KeyInfo] from data.
// The parsed key contents alias a slice of data.
func ParseKeyInfo(data []byte) (KeyInfo, error) {
	if len(data) < 4 {
		return KeyInfo{}, fmt.Errorf("key truncated (%d < 4)", len(data))
	}
	id := int(binary.BigEndian.Uint32(data))
	if id == 0 {
		return KeyInfo{}, errors.New("invalid key ID")
	}
	return KeyInfo{ID: id, Key: data[4:]}, nil
}

// ParseActiveKey parses the binary encoding of an active key ID from data.
func ParseActiveKey(data []byte) (int, error) {
	if len(data) == 0 {
		return 0, nil
	} else if len(data) != 4 {
		return 0, fmt.Errorf("wrong data length (%d ≠ 4)", len(data))
	}
	return int(binary.BigEndian.Uint32(data)), nil
}

// Keyring is the parsed representation of a stored keyring.
type Keyring struct {
	Version  byte    // currently 1 is the only legal value
	Reserved [2]byte // must be zero in version 1
	Packets  []Packet
}

// Packet is the parsed representation of a stored packet.
type Packet struct {
	Type PacketType
	Data []byte // format depends on type
}

// Decrypt decryptes the contents of r using the specified key.
func (r Packet) Decrypt(key []byte) ([]byte, error) {
	return cipher.DecryptWithKey(key, r.Data, nil)
}

// IsValid reports whether r has a valid type.
func (r Packet) IsValid() bool { return r.Type != 0 }

// String renders a human-readable representation of r.
func (r Packet) String() string {
	data := string(r.Data[:min(len(r.Data), 16)])
	return fmt.Sprintf("Packet(type=%v, data=%#q)", r.Type, data)
}

// MagicByte is the initial byte of the binary encoding of a keyring.
const MagicByte = 0xec

// ParseKeyring parses the binary contents of a keyring from data.
// In case of error, it returns partial results.
// The caller is responsible for validating the Version and Reserved fields,
// as well as packet types.
// The contents of the parsed packets alias slices of data.
func ParseKeyring(data []byte) (Keyring, error) {
	if len(data) < 4 {
		return Keyring{}, errors.New("invalid keyring: header truncated")
	} else if data[0] != MagicByte {
		return Keyring{}, errors.New("invalid keyring: invalid header")
	}
	rk := Keyring{
		Version:  data[1],
		Reserved: [2]byte{data[2], data[3]},
	}
	pkt, err := ParsePackets(data[4:], 4)
	rk.Packets = pkt
	return rk, err
}

// ParsePackets parses the contents of data into raw packets.
// The base offset is added to position information in errors.
// In case of error, all complete packets so far are reported.
// The contents of the parsed packets alias slices of data.
func ParsePackets(data []byte, base int) ([]Packet, error) {
	var out []Packet
	cur := data
	for len(cur) != 0 {
		if len(cur) < 4 {
			return out, fmt.Errorf("offset %d: truncated packet header", base+len(data)-len(cur))
		}
		pt := PacketType(cur[0])
		plen := uint24(cur[1:])
		cur = cur[4:]
		if len(cur) < int(plen) {
			return out, fmt.Errorf("offset %d: truncated packet (%d < %d)", base+len(data)-len(cur), len(cur), plen)
		}

		out = append(out, Packet{
			Type: pt,
			Data: cur[:int(plen)],
		})
		cur = cur[int(plen):]
	}
	return out, nil
}

// PacketType identifies the type of a packet in the binary storage format.
type PacketType byte

const (
	DataKeyType       PacketType = 2 // encrypted data key
	AccessKeySaltType PacketType = 3 // access key generation salt
	KeyringEntryType  PacketType = 4 // stored keyring key
	ActiveKeyType     PacketType = 5 // active key ID
	BundleType        PacketType = 6 // encrypted bundle
)

func (p PacketType) String() string {
	switch p {
	case DataKeyType:
		return "DATA_KEY"
	case AccessKeySaltType:
		return "ACCESS_KEY_SALT"
	case KeyringEntryType:
		return "KEYRING_ENTRY"
	case ActiveKeyType:
		return "ACTIVE_KEY_ID"
	case BundleType:
		return "BUNDLE"
	default:
		return fmt.Sprintf("UNKNOWN_TYPE_%d", p)
	}
}

// A Buffer is a writable builder for an encoded packet.
// It wraps and is usable as a [bytes.Buffer].
type Buffer struct {
	bytes.Buffer
}

// WriteHeader writes a format header with the specified version byte.
func (p *Buffer) WriteHeader(format byte, reserved [2]byte) {
	p.WriteByte(MagicByte)
	p.WriteByte(format)
	p.Write(reserved[:])
}

// AddPacket adds a packet to p with the given type and contents.
func (p *Buffer) AddPacket(pt PacketType, data []byte) {
	if len(data) > maxUint24 {
		panic(fmt.Sprintf("packet too big (%d > %d)", len(data), maxUint24))
	}
	var buf [4]byte
	binary.BigEndian.PutUint32(buf[:], uint32(len(data)))
	buf[0] = byte(pt)
	p.Write(buf[:])
	p.Write(data)
}

// AddActiveKey adds an [ActiveKeyType] packet to p.
func (p *Buffer) AddActiveKey(id int) {
	p.AddPacket(ActiveKeyType, binary.BigEndian.AppendUint32(nil, uint32(id)))
}

// AddKeyringEntry adds a [KeyringEntryType] packet to p.
func (p *Buffer) AddKeyringEntry(ki KeyInfo) {
	var buf []byte
	buf = binary.BigEndian.AppendUint32(buf, uint32(ki.ID))
	buf = append(buf, ki.Key...)
	p.AddPacket(KeyringEntryType, buf)
}

const maxUint24 = 1<<24 - 1

func uint24(data []byte) uint32 {
	return uint32(data[0])<<16 | uint32(data[1])<<8 | uint32(data[2])
}
