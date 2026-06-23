# sqlite

**Org:** hanzoai · **Ecosystem:** hanzo · **Path:** `/Users/a/work/hanzo/hanzoai/sqlite`
**Origin:** https://github.com/hanzoai/sqlite.git · **Module:** `github.com/hanzoai/sqlite`

Dual-backend `database/sql` driver. Registers the driver name **`sqlite`** under
BOTH build configs with one public API:

| Build | Backend | Encryption |
|-------|---------|------------|
| `CGO_ENABLED=1` + `-tags libsqlite3` + libsqlcipher | mattn/go-sqlite3 → SQLCipher | AES-256 at rest |
| `CGO_ENABLED=0` | modernc.org/sqlite (pure Go) | none (fail-secure: keyed Open errors) |

## File map (decomplected by what actually varies)

- `sqlite.go` — tag-neutral: `Config`, `Option`, `WithKey/WithRawKey/WithPrincipalKey/…`, `DB`, `Open()`, `EncryptionAvailable()`, `CodecLinked()` (runtime codec probe).
- `cek.go` — tag-neutral, pure Go: `DeriveKey` (HKDF-SHA256, length-prefixed injective info → KEK), `DeriveChildKey` (hierarchy), envelope `NewDEK`/`WrapDEK`/`UnwrapDEK` (AES-256-GCM; take a principal-binding `aad`), `PrincipalAAD` (the injective `(type,id)` encoding reused as the GCM AAD — DRY), `PrincipalGlobal/Org/User`.
- `threshold.go` — tag-neutral, pure Go: `ThresholdManager` (t-of-n Ed25519 write attestation).
- `driver_cgo.go` (`//go:build cgo`) — registers `sqlite`→mattn; `EncryptionAvailable()=true`; `OpenDB`/`DSN` emit SQLCipher URI key; path is percent-escaped so `?`/`#` can't strip `key=`.
- `driver_nocgo.go` (`//go:build !cgo`) — blank-imports modernc (self-registers `sqlite`); `EncryptionAvailable()=false`; keyed open → `ErrEncryptionUnavailable`.
- `encryption_proof_test.go` — anti-silent-plaintext gate (real ciphertext + reopen + wrong-key rejection under cgo, SKIPs if codec unlinked) + envelope rotation/injectivity/hierarchy proofs (run under both tags).

## Envelope encryption — rotation-safe (read before touching key handling)

Each database has its OWN random 256-bit **DEK** (`NewDEK`), set once at
creation; SQLCipher encrypts pages with it and it NEVER changes. The DEK is
**wrapped** (AES-256-GCM) under a **KEK** = `DeriveKey(masterKey, principal, id)`
and the wrapped blob is stored beside the file (consumer owns the sidecar). To
open: unwrap with the KEK → DEK → SQLCipher. To **rotate the master key**:
unwrap with the old KEK, rewrap with the new KEK, replace the sidecar — the DEK
is unchanged so pages are untouched, O(1), never bricks. (The old "page key =
HKDF(master)" scheme could not rotate: a new master changed the page key and
SQLCipher rejected every existing file.)

HKDF `info` is **length-prefixed** (`lp(type)||lp(id)`) → injective, so
`(org,"a:b")` ≠ `("org:a","b")`. The SAME encoding is exposed as `PrincipalAAD`
and bound into the wrap as GCM **AAD** (`WrapDEK(kek, dek, aad)` /
`UnwrapDEK(kek, blob, aad)`), so a wrapped DEK is also cryptographically bound to
its principal — a sidecar moved to another principal fails the tag even if a KEK
ever collided (defense-in-depth). The on-disk AAD is `version-byte || aad`, so a
version downgrade is unforgeable too. `cache=shared` is applied ONLY to
unencrypted DSNs — on a keyed DB the shared page cache holds DECRYPTED pages and
a wrong-key reopen would read them (isolation break), so it is never set on
encrypted files.

## CRITICAL — how SQLCipher actually works here (don't repeat the bug)

mainline `mattn/go-sqlite3` has **NO `sqlcipher` build tag** and no `sqlite3_key`
binding. `-tags sqlcipher` is **inert → ships PLAINTEXT**. It also **cannot reopen**
a SQLCipher DB from a `ConnectHook` (mattn runs `PRAGMA busy_timeout/journal_mode/…`
before the hook → "file is not a database"). Proven dead ends. The working path:

```sh
CGO_ENABLED=1 \
CGO_CFLAGS="-DSQLITE_HAS_CODEC -DSQLITE_USE_URI=1 -I<sqlcipher>/include/sqlcipher" \
CGO_LDFLAGS="-lsqlcipher" \
go build -tags "libsqlite3 sqlite_fts5" ./...
```

The key rides the DSN as SQLCipher's **native URI param** `file:PATH?...&key=x'HEX'`,
applied inside `sqlite3_open_v2` before any pragma → create AND reopen work.
**Never log the DSN** (it contains the key). `TestEncryptionProof` fails a
mis-linked build instead of shipping plaintext.

**The `Dockerfile` builds with this exact recipe** (`-tags "libsqlite3
sqlite_fts5"` + the codec CFLAGS/LDFLAGS, headers under `/usr/include/sqlcipher`
from Debian `libsqlcipher-dev`) and runs the test stage with
`SQLITE_REQUIRE_CODEC=1`, which turns `TestEncryptionProof`'s "codec unlinked"
SKIP into a HARD FAILURE — so the image's own gate asserts real ciphertext and a
regression to the inert `-tags sqlcipher` recipe fails the build. (Earlier the
Dockerfile used the inert tags → `CodecLinked()=false` → the proof silently
skipped: a green build proving nothing.)

## Consumers

Hanzo IAM (`object/orgdb.go`) per-org encrypted DBs: `OpenDB(path, DeriveKey(mk,
PrincipalOrg, slug))` → `xorm.NewEngineWithDB("sqlite", "", core.FromDB(db))`.

## Versioning

PATCH bumps only (v0.1.x). Current: v0.1.4.

- v0.1.4 — `WrapDEK`/`UnwrapDEK` take a principal-binding GCM `aad` + add
  `PrincipalAAD` (defense-in-depth). Dockerfile fixed to link the codec and
  self-assert via `SQLITE_REQUIRE_CODEC=1` (was inert-tag CI-theater).
