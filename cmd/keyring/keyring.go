// Copyright (C) 2025 Michael J. Fromberger. All Rights Reserved.

// Program keyring is a command-line tool to manipulate keyring files.
package main

import (
	crand "crypto/rand"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"unicode/utf8"

	"github.com/creachadair/atomicfile"
	"github.com/creachadair/command"
	"github.com/creachadair/flax"
	"github.com/creachadair/getpass"
	"github.com/creachadair/keyring"
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
