# keyring

[![GoDoc](https://img.shields.io/static/v1?label=godoc&message=reference&color=mediumaquamarine)](https://pkg.go.dev/github.com/creachadair/keyring)
<!-- [![CI](https://github.com/creachadair/keyring/actions/workflows/go-presubmit.yml/badge.svg?event=push&branch=main)](https://github.com/creachadair/keyring/actions/workflows/go-presubmit.yml) -->

The `keyring` package provides an interface to read and write encryption keys
and other sensitive secrets in a persistent format protected by a secret key.
The stored key material are symmetrically encrypted with chacha20poly1305.
