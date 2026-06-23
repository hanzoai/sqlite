# Hanzo SQLite

Dual-backend SQLite driver for the Hanzo ecosystem. Registers the
`database/sql` driver name **`sqlite`** under both build configurations and
exposes the same API either way:

| Build | Backend | Encryption | Use |
|-------|---------|------------|-----|
| `CGO_ENABLED=1` + `-tags libsqlite3` + libsqlcipher | mattn/go-sqlite3 → SQLCipher | AES-256 page-level, at rest | **production** |
| `CGO_ENABLED=0` | modernc.org/sqlite (pure Go) | none | CI tests / lint / local dev |

One import, one driver name, two backends:

```go
import _ "github.com/hanzoai/sqlite" // registers "sqlite" under both tags

db, _ := sql.Open("sqlite", dsn)     // mattn+SQLCipher (cgo) or modernc (!cgo)
```

The pure-Go backend **cannot encrypt**. Demanding a key on it
(`Open(path, WithKey(...))`, `OpenDB(path, key)`) returns
`ErrEncryptionUnavailable` and writes nothing — it never silently persists
plaintext.

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
  param, or derived per principal:

```go
// CEK = HKDF-SHA256(masterKey, "{org|user}:{id}")
db, _ := sqlite.Open("data.db", sqlite.WithPrincipalKey(masterKey, sqlite.PrincipalOrg, "acme"))

// Or get a *sql.DB to hand to xorm.NewEngineWithDB:
cek, _ := sqlite.DeriveKey(masterKey, sqlite.PrincipalOrg, "acme")
sqldb, _ := sqlite.OpenDB(dbPath, cek)
eng, _ := xorm.NewEngineWithDB("sqlite", "", core.FromDB(sqldb))
```

Different orgs/users get different CEKs (domain-separated `info`); destroying the
master key renders every derived CEK irrecoverable.

## Per-principal CEK

`DeriveKey(masterKey, principalType, principalID)` → 32-byte CEK via HKDF-SHA256.
Master key is 32 bytes, sourced from KMS. Used for per-org and per-user database
isolation in IAM, KMS, and other Hanzo services.

## Threshold write attestation

`ThresholdManager` coordinates t-of-n Ed25519 attestations for writes (MPC shard
storage, multi-sig). Pure Go; available under both backends.

## License

Apache-2.0
