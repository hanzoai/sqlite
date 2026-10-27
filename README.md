<p align="center"><img src=".github/hero.svg" alt="sqlite" width="880"></p>

# Hanzo SQLite

Dual-backend SQLite driver for the Hanzo ecosystem. Registers the
`database/sql` driver name **`sqlite`** under both build configurations and
exposes the same API either way:

| Build | Backend | Keyed-Store Encryption | Use |
|-------|---------|------------------------|-----|
| `CGO_ENABLED=1` + `-tags libsqlite3` + libsqlcipher | hanzoai/csqlite → SQLCipher | Live SQLCipher if linked; codec envelope otherwise | **production** |
| `CGO_ENABLED=1` + `-tags sqlite_purego` | modernc.org/sqlite (pure Go) | SQLCipher-compatible codec envelope (`sqlite3-codec-envelope`) | CI / lint / local dev |
| `CGO_ENABLED=0` | modernc.org/sqlite (pure Go) | SQLCipher-compatible codec envelope (`sqlite3-codec-envelope`) | CI tests / lint / local dev |

One import, one driver name, two backends:

```go
package main

import (
	"database/sql"

	_ "github.com/hanzoai/sqlite" // registers "sqlite" under both tags
)

func main() {
	db, err := sql.Open("sqlite", "file:data.db") // hanzoai/csqlite (cgo) or modernc (!cgo)
	if err != nil {
		panic(err)
	}
	defer db.Close()
}
```

A keyed store is encrypted on **every** build — there is no fallback to plaintext.
The pure-Go backend (`CGO_ENABLED=0`) wraps modernc with the SQLCipher-compatible
codec envelope (`database/sql` driver registered as `sqlite3-codec-envelope`),
decrypting to a RAM-backed copy on open and re-encrypting on close and checkpoint.
The cgo backend uses live libsqlcipher when linked, and automatically falls back to
the pure-Go codec envelope if live libsqlcipher is not linked. Opening without a key
operates as unencrypted plaintext.

## Building the encrypted (production) backend — READ THIS

The `hanzoai/csqlite` driver has **no `sqlcipher` build tag** and no
`sqlite3_key()` binding. SQLCipher works only when you:

1. link the **system** sqlite (the `libsqlite3` tag) against **libsqlcipher**, and
2. enable the codec + URI keying via CGO flags, and
3. supply the key as SQLCipher's **native URI `key` parameter** so it is applied
   inside `sqlite3_open_v2` — *before* csqlite's pragma battery runs.

```sh
CGO_ENABLED=1 \
CGO_CFLAGS="-DSQLITE_HAS_CODEC -DSQLITE_USE_URI=1 -I<sqlcipher>/include/sqlcipher" \
CGO_LDFLAGS="-L<sqlcipher>/lib -lsqlcipher" \
go build -tags "libsqlite3 sqlite_fts5" ./...
```

Alpine: `apk add gcc musl-dev sqlcipher-dev pkgconfig`.

### Why not `-tags sqlcipher` + `PRAGMA key` in a ConnectHook?

Both are traps that ship **plaintext**:

- `-tags sqlcipher` is inert in csqlite (no such tag) → links plain
  sqlite → `PRAGMA key` is a silent no-op.
- csqlite runs `PRAGMA busy_timeout/journal_mode/foreign_keys/...` via
  `sqlite3_exec` **before** the ConnectHook fires. On an existing encrypted file
  that touches the header before the key is set → `file is not a database` on
  reopen. So a ConnectHook can *create* but never *reopen* a SQLCipher DB.

The URI `key` parameter sidesteps both: SQLCipher's VFS keys the connection at
open time. `TestEncryptionProof` asserts real ciphertext on disk and a working
keyed reopen, so a mis-linked build **fails CI** instead of shipping plaintext.

> On the live cgo path, the key rides the DSN (`file:PATH?...&key=x'HEX'`).
> **Never log the DSN.**
> IAM keeps `showSql=false` and does not log it.

## Encryption

- Algorithm: AES-256 (SQLCipher 4 defaults: 4096-byte pages, PBKDF2-HMAC-SHA512,
  256000 iters, per-page HMAC-SHA512).
- Key: raw 256-bit key supplied via `sqlite.WithRawKey` or `sqlite.OpenDB`. `WithKey`
  hashes a passphrase once with SHA-256 and is suitable only for a high-entropy secret;
  it is not a password-hardening KDF. For passphrase-based keys, derive a key out of
  band with a salted KDF (e.g., Argon2id or PBKDF2) and pass it via `WithRawKey`.

```go
package main

import (
	"database/sql"
	"encoding/hex"
	"log"
	"os"

	sqlite "github.com/hanzoai/sqlite"
)

func main() {
	// 32-byte raw key (e.g. from KMS or secret manager); never log the key.
	key, err := hex.DecodeString(os.Getenv("SQLITE_KEY_HEX"))
	if err != nil {
		log.Fatal(err)
	}

	// Open using high-level sqlite.Open with WithRawKey:
	db, err := sqlite.Open("data.db", sqlite.WithRawKey(key))
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	// Or obtain a *sql.DB directly using OpenDB:
	sqldb, err := sqlite.OpenDB("data.db", key)
	if err != nil {
		log.Fatal(err)
	}
	defer sqldb.Close()
}
```

### Application-Level Key Derivation (Per-Principal CEK)

Per-principal database isolation is an application-level pattern rather than a driver primitive.
Callers derive a 32-byte Content Encryption Key (CEK) from a root master key (for example, using
HKDF-SHA256 with tenant, org, or user identity as domain separation info) and pass the resulting
raw key to `sqlite.WithRawKey(cek)` or `sqlite.OpenDB(path, cek)`. Destroying the master key renders
all derived CEKs irrecoverable.

## Threshold write attestation

`ThresholdManager` coordinates t-of-n Ed25519 attestations for writes (MPC shard
storage, multi-sig). Pure Go; available under both backends.

## License

MIT OR Apache-2.0, at your option — per [HIP-0137](https://github.com/hanzoai/hips/blob/main/HIPs/hip-0137-one-license.md).
