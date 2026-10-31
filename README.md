<p align="center"><img src=".github/hero.svg" alt="sqlite" width="880"></p>

# Hanzo SQLite

Dual-backend SQLite driver for the Hanzo ecosystem. Registers the
`database/sql` driver name **`sqlite`** under both build configurations and
exposes the same API either way:

| Build | Backend | Encryption | Use |
|-------|---------|------------|-----|
| `CGO_ENABLED=1` + `-tags libsqlite3` + libsqlcipher | hanzoai/csqlite → live SQLCipher | AES-256 page-level, at rest | **production** |
| `CGO_ENABLED=0` (or `-tags sqlite_purego`) | modernc.org/sqlite (pure Go) | AES-256 at rest, via the pure-Go SQLCipher codec envelope | CI tests / lint / local dev, and any keyed store |

One import, one driver name, two backends:

```go
import _ "github.com/hanzoai/sqlite" // registers "sqlite" under both tags

db, _ := sql.Open("sqlite", dsn)     // hanzoai/csqlite (cgo) or modernc (pure Go)
```

A keyed store encrypts under both `CGO_ENABLED=1` and `CGO_ENABLED=0`. On the
pure-Go build the `hanzoai/sqlcipher` codec does it: a keyed open decrypts to a
RAM-backed copy, and `Close`/`Checkpoint` re-encrypts it to the real path.
`EncryptionAvailable()` is always true.

## Building the encrypted (production) backend — READ THIS

mainline `mattn/go-sqlite3` has **no `sqlcipher` build tag** and no
`sqlite3_key()` binding. SQLCipher works only when you:

1. link the **system** sqlite (the `libsqlite3` tag) against **libsqlcipher**, and
2. enable the codec + URI keying via CGO flags, and
3. supply the key as SQLCipher's **native URI `key` parameter** so it is applied
   inside `sqlite3_open_v2` — *before* mattn's pragma battery runs.

```sh
CGO_ENABLED=1 \
CGO_CFLAGS="-DSQLITE_HAS_CODEC -DSQLITE_USE_URI=1 -I<sqlcipher>/include/sqlcipher" \
CGO_LDFLAGS="-L<sqlcipher>/lib -lsqlcipher" \
go build -tags "libsqlite3 sqlite_fts5" ./...
```

Alpine: `apk add gcc musl-dev sqlcipher-dev pkgconfig`.

### Why not `-tags sqlcipher` + `PRAGMA key` in a ConnectHook?

Both are traps that ship **plaintext**:

- `-tags sqlcipher` is inert in mainline mattn (no such tag) → links plain
  sqlite → `PRAGMA key` is a silent no-op.
- mattn runs `PRAGMA busy_timeout/journal_mode/foreign_keys/...` via
  `sqlite3_exec` **before** the ConnectHook fires. On an existing encrypted file
  that touches the header before the key is set → `file is not a database` on
  reopen. So a ConnectHook can *create* but never *reopen* a SQLCipher DB.

The URI `key` parameter sidesteps both: SQLCipher's VFS keys the connection at
open time. `TestEncryptionProof` asserts real ciphertext on disk and a working
keyed reopen, so a mis-linked build **fails CI** instead of shipping plaintext.

> The key rides the DSN (`file:PATH?...&key=x'HEX'`). **Never log the DSN.**
> IAM keeps `showSql=false` and does not log it.

## Encryption

- Algorithm: AES-256 (SQLCipher 4 defaults: 4096-byte pages, PBKDF2-HMAC-SHA512,
  256000 iters, per-page HMAC-SHA512).
- Key: raw 256-bit, supplied three equivalent ways — `WithRawKey(key)`,
  `OpenDB(path, key)`, or the `key=x'HEX'` DSN param:

```go
key := make([]byte, 32) // 32 bytes from KMS or any CSPRNG — not a passphrase

db, _ := sqlite.Open("data.db", sqlite.WithRawKey(key))

// Or get a *sql.DB for a library that wants one:
sqldb, _ := sqlite.OpenDB(dbPath, key)
```

A key must be exactly 32 bytes or the open fails. `WithKey(passphrase)` hashes
with one unsalted SHA-256, so it is safe only for a high-entropy secret; for a
memorable passphrase, derive 32 bytes yourself with argon2id or PBKDF2 and pass
them to `WithRawKey`.

Per-principal keys (one per org or user) are derived outside this package: run
your own KDF over a KMS master key, for example HKDF-SHA256, and pass the 32
bytes to `WithRawKey` or `OpenDB`.

## Threshold write attestation

`ThresholdManager` coordinates t-of-n Ed25519 attestations for writes (MPC shard
storage, multi-sig). Pure Go; available under both backends.

## License

MIT OR Apache-2.0, at your option — per [HIP-0137](https://github.com/hanzoai/hips/blob/main/HIPs/hip-0137-one-license.md).
