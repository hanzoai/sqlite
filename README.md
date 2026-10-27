<p align="center"><img src=".github/hero.svg" alt="sqlite" width="880"></p>

# Hanzo SQLite

Dual-backend SQLite driver for the Hanzo ecosystem. Registers the
`database/sql` driver name **`sqlite`** under both build configurations and
exposes the same API either way:

| Build | Backend | Encryption | Use |
|-------|---------|------------|-----|
| `CGO_ENABLED=1` + `-tags libsqlite3` + libsqlcipher | mattn/go-sqlite3 → SQLCipher | AES-256 page-level, at rest | **production** |
| `CGO_ENABLED=0` | modernc.org/sqlite (pure Go) | AES-256, at rest | CI tests / lint / local dev |

One import, one driver name, two backends:

```go
import _ "github.com/hanzoai/sqlite" // registers "sqlite" under both tags

db, _ := sql.Open("sqlite", dsn)     // mattn+SQLCipher (cgo) or modernc (!cgo)
```

A keyed store is encrypted on **every** build, including the pure-Go
backend. Pass a raw 256-bit key via `WithRawKey` or the `key=x'HEX'` DSN
parameter and the driver encrypts at rest regardless of `CGO_ENABLED`.
`TestEncryptionProof` asserts real ciphertext on disk and a working keyed
reopen under both backends.

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
- Key: raw 256-bit (no passphrase KDF) via `WithRawKey` / the `key=x'HEX'` DSN
  param:

```go
db, _ := sqlite.Open("data.db", sqlite.WithRawKey(masterKey))

// Or get a *sql.DB to hand to xorm.NewEngineWithDB:
sqldb, _ := sqlite.OpenDB(dbPath, masterKey)
eng, _ := xorm.NewEngineWithDB("sqlite", "", core.FromDB(sqldb))
```

The master key is 32 bytes, sourced from KMS. Destroying the master key renders
the database irrecoverable.

## Threshold write attestation

`ThresholdManager` coordinates t-of-n Ed25519 attestations for writes (MPC shard
storage, multi-sig). Pure Go; available under both backends.

## License

MIT OR Apache-2.0, at your option — per [HIP-0137](https://github.com/hanzoai/hips/blob/main/HIPs/hip-0137-one-license.md).
