// Copyright (C) 2025 Michael J. Fromberger. All Rights Reserved.

// Program keyring is a command-line tool to manipulate keyring files.
package main

import (
	crand "crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"unicode/utf8"

	"github.com/creachadair/atomicfile"
	"github.com/creachadair/command"
	"github.com/creachadair/flax"
	"github.com/creachadair/getpass"
	"github.com/creachadair/keyring"
	"github.com/creachadair/keyring/internal/packet"
)

var flags struct {
	EmptyOK bool `flag:"empty-ok,PRIVATE:Allow an empty passphrase"`
}

func main() {
	root := &command.C{
		Name:     command.ProgramName(),
		Help:     `Create and manipulate the contents of keyring files.`,
		SetFlags: command.Flags(flax.MustBind, &flags),

		Commands: []*command.C{
			{
				Name:     "create",
				Usage:    "<keyring> --random n\n<keyring> <initial-key>",
				Help:     `Create a new keyring file.`,
				SetFlags: command.Flags(flax.MustBind, &createFlags),
				Run:      command.Adapt(runCreate),
			},
			{
				Name:     "list",
				Usage:    "<keyring>",
				Help:     `List the keys in a keyring file.`,
				SetFlags: command.Flags(flax.MustBind, &listFlags),
				Run:      command.Adapt(runList),
			},
			{
				Name:     "add",
				Usage:    "<keyring> --random n\n<keyring> <new-key>",
				Help:     `Add a new key to the keyring.`,
				SetFlags: command.Flags(flax.MustBind, &addFlags),
				Run:      command.Adapt(runAdd),
			},
			{
				Name:  "activate",
				Usage: "<keyring> <id>",
				Help:  `Set the current active version in the keyring.`,
				Run:   command.Adapt(runActivate),
			},
			{
				Name:     "debug",
				Help:     `Commands for debugging and inspection.`,
				Unlisted: true,
				Commands: []*command.C{
					{
						Name:     "parse",
						Usage:    "<keyring>",
						Help:     `Parse the binary format of the keyring.`,
						SetFlags: command.Flags(flax.MustBind, &parseFlags),
						Run:      command.Adapt(runDebugParse),
					},
				},
			},
			command.HelpCommand(nil),
			command.VersionCommand(),
		},
	}
	command.RunOrFail(root.NewEnv(nil), os.Args[1:])
}

var createFlags struct {
	Random int `flag:"random,Generate a random initial key of this length"`
}

func runCreate(env *command.Env, name string, args ...string) error {
	initialKey, err := getKeyFromArgs(env, args, createFlags.Random)
	if err != nil {
		return err
	}

	f, err := os.OpenFile(name, os.O_RDWR|os.O_CREATE|os.O_EXCL, 0700)
	if err != nil {
		return err
	}
	defer f.Close()

	pp, err := getPassphrase("New ", true)
	if err != nil {
		return err
	}
	accessKey, accessKeySalt := keyring.AccessKeyFromPassphrase(pp)
	r, err := keyring.New(keyring.Config{
		InitialKey:    initialKey,
		AccessKey:     accessKey,
		AccessKeySalt: accessKeySalt,
	})
	if err != nil {
		return err
	}
	nw, werr := r.WriteTo(f)
	if werr == nil {
		fmt.Fprintf(env, "Wrote %d bytes to %q\n", nw, filepath.Base(name))
	}
	return errors.Join(werr, f.Close())
}

var listFlags struct {
	ShowKeys bool `flag:"show-keys,Show the contents of the keys"`
}

func runList(env *command.Env, name string) error {
	r, err := openAndReadKeyring(name)
	if err != nil {
		return err
	}

	n := r.Len()
	active := r.Active()
	fmt.Printf("# %d total\n", n)
	for id := 1; id <= n; id++ {
		if !r.Has(id) {
			continue
		}
		key := r.Append(id, nil)
		fmt.Printf("%d: ", id)
		if listFlags.ShowKeys {
			if utf8.Valid(key) {
				fmt.Printf("%q", key)
			} else {
				fmt.Printf("%x", key)
			}
		} else {
			fmt.Printf("%d bytes", len(key))
		}
		if id == active {
			fmt.Print(" [active]")
		}
		fmt.Println()
	}
	return nil
}

var addFlags struct {
	Random   int  `flag:"random,Generate a random key of this length"`
	Activate bool `flag:"activate,Mark the new key as active immediately"`
}

func runAdd(env *command.Env, name string, args ...string) error {
	newKey, err := getKeyFromArgs(env, args, addFlags.Random)
	if err != nil {
		return err
	}

	r, err := openAndReadKeyring(name)
	if err != nil {
		return err
	}

	id := r.Add(newKey)
	fmt.Printf("Added key id %d (%d bytes)\n", id, len(newKey))
	if addFlags.Activate {
		r.Activate(id)
		fmt.Printf("Activated new key id %d\n", id)
	}
	return atomicfile.Tx(name, 0700, func(w io.Writer) error {
		nw, err := r.WriteTo(w)
		if err == nil {
			fmt.Fprintf(env, "Wrote %d bytes to %q\n", nw, filepath.Base(name))
		}
		return err
	})
}

func runActivate(env *command.Env, name, idStr string) error {
	id, err := strconv.Atoi(idStr)
	if err != nil {
		return err
	} else if id <= 0 {
		return fmt.Errorf("invalid id %d", id)
	}

	r, err := openAndReadKeyring(name)
	if err != nil {
		return err
	}

	if !r.Has(id) {
		return fmt.Errorf("no key with id %d in keyring", id)
	} else if r.Active() == id {
		fmt.Fprintf(env, "Key id %d is already active\n", id)
		return nil
	}

	r.Activate(id)
	fmt.Printf("Activated key id %d\n", id)
	return atomicfile.Tx(name, 0700, func(w io.Writer) error {
		nw, err := r.WriteTo(w)
		if err == nil {
			fmt.Fprintf(env, "Wrote %d bytes to %q\n", nw, filepath.Base(name))
		}
		return err
	})
}

var parseFlags struct {
	Decrypt bool `flag:"decrypt,Decrypt encrypted bundles (requires passphrase)"`
}

func runDebugParse(env *command.Env, name string) error {
	data, err := os.ReadFile(name)
	if err != nil {
		return err
	}

	kr, err := packet.ParseKeyring(data)
	if err != nil {
		return err
	}

	// If we're supposed to decrypt and there are any bundles, grobble through
	// for a data key and decrypt it. We're not being too picky here, if there
	// are multiple key or salt packets we'll just try the first one.
	var dataKey []byte
	if parseFlags.Decrypt && slices.ContainsFunc(kr.Packets, func(p packet.Packet) bool {
		return p.Type == packet.BundleType
	}) {
		saltp := slices.IndexFunc(kr.Packets, func(p packet.Packet) bool { return p.Type == packet.AccessKeySaltType })
		datap := slices.IndexFunc(kr.Packets, func(p packet.Packet) bool { return p.Type == packet.DataKeyType })
		if saltp < 0 || datap < 0 {
			return errors.New("no data key found for encrypted bundles")
		}

		fmt.Fprintln(env, "Found encrypted bundles, passphrase required to decrypt")
		pp, err := getPassphrase("", false)
		if err != nil {
			return err
		}
		accessKey := keyring.PassphraseKey(pp)(kr.Packets[saltp].Data)
		dk, err := kr.Packets[datap].Decrypt(accessKey)
		if err != nil {
			return fmt.Errorf("invalid access key: %w", err)
		}
		dataKey = dk
		fmt.Fprintln(env, "Unlocked data storage key")
	}
	fmt.Printf("Keyring version %02x, reserved %04x, %d packets\n", kr.Version, kr.Reserved[:], len(kr.Packets))

	for i, pkt := range kr.Packets {
		if i > 0 {
			fmt.Println()
		}
		fmt.Printf("-- Packet %d: %v (%d bytes)\n", i+1, pkt.Type, len(pkt.Data))
		if pkt.Type != packet.BundleType || dataKey == nil {
			hexDump(os.Stdout, pkt.Data, "")
			continue
		}

		// Reaching here, we have an encrypted bundle and are supposed to decrypt it.
		dec, err := pkt.Decrypt(dataKey)
		if err != nil {
			return fmt.Errorf("decrypt packet %d: %w", i+1, err)
		}
		b, err := packet.ParsePackets(dec, 0)
		if err != nil {
			return fmt.Errorf("parse bundle %d: %w", i+1, err)
		}

		for j, pkt := range b {
			if j > 0 {
				fmt.Println()
			}
			fmt.Printf(" + inner packet %d.%d: %v (%d bytes)\n", i+1, j+1, pkt.Type, len(pkt.Data))
			switch pkt.Type {
			case packet.ActiveKeyType:
				fmt.Printf("   active key id: %d\n", binary.BigEndian.Uint32(pkt.Data))
			case packet.KeyringEntryType:
				ki, err := packet.ParseKeyInfo(pkt.Data)
				if err != nil {
					fmt.Printf("   <invalid key info> %v\n", err)
					break
				}
				fmt.Printf("   ID: %v, Key: ", ki.ID)
				if utf8.Valid(ki.Key) {
					fmt.Printf("%q\n", ki.Key)
				} else {
					fmt.Printf("%x\n", ki.Key)
				}
			default:
				hexDump(os.Stdout, pkt.Data, "     ")
			}
		}
	}
	return nil
}

func hexDump(w io.Writer, data []byte, indent string) {
	const numCols = 16

	col := 0
	for _, b := range data {
		if col == 0 {
			fmt.Fprint(w, indent)
		} else {
			fmt.Fprint(w, " ")
		}
		if b >= ' ' && b < 0x80 {
			fmt.Fprintf(w, " %c", b)
		} else {
			fmt.Fprintf(w, "%02x", b)
		}
		col++
		if col == numCols {
			fmt.Fprintln(w)
			col = 0
		}
	}
	if col > 0 {
		fmt.Fprintln(w)
	}
}

func openAndReadKeyring(name string) (*keyring.Ring, error) {
	f, err := os.Open(name)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	pp, err := getPassphrase("", false)
	if err != nil {
		return nil, err
	}
	return keyring.Read(f, keyring.PassphraseKey(pp))
}

func getPassphrase(tag string, confirm bool) (string, error) {
	pp, err := getpass.Prompt(tag + "Passphrase: ")
	if err != nil {
		return "", fmt.Errorf("read passphrase: %w", err)
	} else if pp == "" && confirm && !flags.EmptyOK {
		return "", errors.New("empty passphrase")
	}
	if confirm {
		cf, err := getpass.Prompt("Confirm " + tag + "passphrase: ")
		if err != nil {
			return "", fmt.Errorf("read confirmation: %w", err)
		} else if cf != pp {
			return "", errors.New("passphrases do not match")
		}
	}
	return pp, nil
}

func getKeyFromArgs(env *command.Env, args []string, random int) ([]byte, error) {
	if len(args) > 1 {
		return nil, env.Usagef("extra arguments after key: %v", args[1:])
	} else if len(args) == 1 {
		if len(args[0]) == 0 {
			return nil, env.Usagef("a key cannot be empty")
		}
		return []byte(args[0]), nil
	} else if random <= 0 {
		return nil, env.Usagef("a key or --random is required")
	}
	key := make([]byte, random)
	crand.Read(key) // panics on error
	fmt.Fprintf(env, "Generated %d-byte random key\n", len(key))
	return key, nil
}
