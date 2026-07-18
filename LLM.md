# sqlite

**Org:** hanzoai · **Ecosystem:** hanzo · **Module:** `github.com/hanzoai/sqlite`
**Origin:** https://github.com/hanzoai/sqlite.git

Dual-backend `database/sql` driver registering the driver name **`sqlite`** under
BOTH build configs with one public API. **Both backends encrypt at rest, in the
SAME SQLCipher-4 on-disk format** — a database written by one opens under the
other.

| Build | Backend | Encryption |
|-------|---------|------------|
| `CGO_ENABLED=0` (default) | **vendored pure-Go engine** (`internal/engine`) + **hanzoai/sqlcipher** codec VFS | AES-256 at rest, **no cgo, no external C lib** |
| `CGO_ENABLED=1` + `-tags libsqlite3` + libsqlcipher | **hanzoai/csqlite** → SQLCipher | AES-256 at rest (C engine, for speed) |

The pure-Go backend is the primary one: it always encrypts, needs nothing linked,
and is what CI/tests/lint/pure-Go deployments use. **`go list -m all` shows ZERO
`modernc.org/*`** — the engine is vendored in-tree.

## Self-containment (how the pure-Go engine is vendored)

`internal/` is a fork of `modernc.org/{sqlite,libc,memory,mathutil}` — the exact
runtime import closure of `modernc.org/sqlite` + `/vfs`, arch-trimmed to
`{linux,darwin}×{amd64,arm64}` (all 64-bit), with every `modernc.org/*` import
rewritten into `github.com/hanzoai/sqlite/internal/*`. No `cc`/`ccgo`/`gc`/
`goabi0`/`fileutil` (those are `//go:build ignore` codegen-only). Base:
**modernc.org/sqlite v1.53.0** (SQLite 3.53.2).

**To re-vendor (bump the engine):** in `scratchpad`/a throwaway module, `go get
modernc.org/sqlite@vX`, then re-run the vendor script (copies the per-arch
`go list` file set for the 4 target arches, rewrites imports), then re-apply the
three engine patches below and drop `codec.go` back into `internal/engine/vfs/`.
The vfs ABI seam (`patches64.go` offsets, `sqlite3_vfs`/`sqlite3_io_methods`/
`VFSFile`/`sqlite_int64` types) has been byte-stable v1.44.3→v1.53.0, so `codec.go`
drops in unchanged.

### The three engine patches (minimal fork delta)
1. `internal/engine/fcntl.go` — `(*conn).fileControlReserveBytes(n)`:
   `SQLITE_FCNTL_RESERVE_BYTES`, so page 1 is created with the 80-byte SQLCipher
   trailer room.
2. `internal/engine/sqlite.go` `applyQueryParams` — handle `_reserve_bytes=N`
   BEFORE any writing pragma (calls the above).
3. `internal/engine/driver.go` — `Connector(dsn)`: a `driver.Connector` so
   `sql.OpenDB` can wrap it in an `io.Closer` (unregister the codec VFS on
   `sql.DB.Close`).

## The pure-Go codec VFS — `internal/engine/vfs/codec.go`

The write side upstream modernc left null. It is a read-write, os-backed
`sqlite3_vfs` whose io_methods (`codecio`, wired via the ccgo reinterpret idiom)
apply the **hanzoai/sqlcipher** page codec on every read/write. `Register(dek)`
mallocs+registers a per-database VFS bound to the DEK and returns an unregister
closer; `driver_nocgo.OpenDB` opens through it with `sql.OpenDB(codecConnector{…})`
so the VFS (and the DEK) are torn down exactly when the `*sql.DB` closes.

**Subtleties that will bite a refactor (all empirically established):**
- **Zero the reserve on decrypt.** SQLCipher's codec is normally a pager hook;
  here it is a VFS shim UNDER the pager, so the engine computes WAL frame (and
  rollback-journal) checksums over the PLAINTEXT page including its 80-byte
  reserve. The codec overwrites that reserve with a fresh IV+HMAC each write, so
  `codecRead` **zeros the reserve region** of every page it returns. The engine
  zeros the full buffer of NEW pages; combined, every page the engine ever
  checksums has a zero reserve → checksum is always over `[data‖zeros]` →
  round-trips. Main-db pages carry no checksum, so zeroing the (pager-ignored)
  reserve there is invisible and the on-disk bytes stay byte-identical to C.
- **In-process shm.** `codecio` is iVersion 2 with `xShmMap/xShmLock/xShmBarrier/
  xShmUnmap`: the wal-index is per-database heap memory (one `shm` per `codecVFS`),
  locks are no-ops. This is why WAL — including the create-time DELETE→WAL
  conversion — works with no `-shm` file. Correct for **exactly one connection**:
  `OpenDB` sets `MaxOpenConns(1)`. A keyed DB is single-writer, single-process.
- **Create through an in-memory journal.** A new DB starts in DELETE mode; its
  first writes and the DELETE→WAL switch need a rollback journal, which the codec
  VFS **refuses** (MAIN_JOURNAL → CANTOPEN, fail-closed — it would put plaintext
  page images on disk). So `openDB` → `ensureWAL`: read `journal_mode`; if not
  `wal`, set `journal_mode=MEMORY` (in-memory rollback journal, no `-journal`
  file) then `journal_mode=WAL`. Already-WAL DBs are left alone (no churn). The
  DELETE→WAL step MUST run on an established connection, not during the
  connection's own setup pragmas.
- **temp_store=MEMORY** keeps temp/statement spill in RAM — no plaintext temp
  files. So the only files on disk are the encrypted main DB and `-wal`.
- **Page size fixed at 4096, reserve 80** (SQLCipher-4 defaults); salt = page 1's
  first 16 bytes in the clear, read on open (existing) or freshly random (new).

## File map

- `sqlite.go` — tag-neutral: `Config`, `Option`, `WithKey/WithRawKey/WithPrincipalKey`, `DB`, `Open()`, `EncryptionAvailable()` (true both tags), `CodecLinked()` (runtime codec probe; true on pure-Go, true on a linked cgo build).
- `cek.go` — tag-neutral, pure Go: envelope key handling (below).
- `threshold.go` — tag-neutral: `ThresholdManager` (t-of-n Ed25519 write attestation).
- `driver_nocgo.go` (`//go:build !cgo`) — imports the vendored engine + codec VFS; `EncryptionAvailable()=true`; keyed `OpenDB` → codec VFS + `ensureWAL`; `DSN(path,nil)` = plain, `DSN(path,key)` panics (the key binds to the VFS, use OpenDB).
- `driver_cgo.go` (`//go:build cgo`) — registers `sqlite`→**hanzoai/csqlite**; keys via SQLCipher URI `key=x'HEX'`; path percent-escaped so `?`/`#` can't strip `key=`.
- `internal/engine/**` — the vendored pure-Go SQLite engine (fork; see above).
- `encryption_proof_test.go`, `sqlcipher_pure_test.go` — anti-silent-plaintext gate + pure-Go WAL round-trip + byte-compat both directions (opens a C-written fixture; decrypts driver-written bytes with the standalone codec).

## Envelope encryption — rotation-safe (read before touching key handling)

Each database has its OWN random 256-bit **DEK** (`NewDEK`), set once at creation;
pages are encrypted with it and it NEVER changes. The DEK is **wrapped**
(AES-256-GCM) under a **KEK** = `DeriveKey(masterKey, principal, id)` and the
wrapped blob is stored beside the file (consumer owns the sidecar). Open: unwrap →
DEK → open. **Rotate the master key:** unwrap with old KEK, rewrap with new KEK,
replace the sidecar — the DEK is unchanged so pages are untouched, O(1), never
bricks.

HKDF `info` is **length-prefixed** (`lp(type)||lp(id)`) → injective, so
`(org,"a:b")` ≠ `("org:a","b")`. The SAME encoding is exposed as `PrincipalAAD`
and bound into the wrap as GCM **AAD**, so a wrapped DEK is cryptographically
bound to its principal (a sidecar moved to another principal fails the tag). The
on-disk AAD is `version-byte || aad`, so a version downgrade is unforgeable.
`cache=shared` is applied ONLY to unencrypted DSNs.

## CGO backend recipe (secondary / perf path)

```sh
CGO_ENABLED=1 \
CGO_CFLAGS="-DSQLITE_HAS_CODEC -DSQLITE_USE_URI=1 -I<sqlcipher>/include/sqlcipher" \
CGO_LDFLAGS="-lsqlcipher" \
go build -tags "libsqlite3 sqlite_fts5" ./...
```

hanzoai/csqlite keys the DB through SQLCipher's native URI param
`file:PATH?...&key=x'HEX'` at `sqlite3_open_v2` time (create AND reopen work).
**Never log the DSN** (it contains the key). A cgo build that forgets to link
libsqlcipher silently writes plaintext; `CodecLinked()` proves the codec at
runtime and `TestEncryptionProof` (with `SQLITE_REQUIRE_CODEC=1` in the Dockerfile
stage) fails such a build.

## Consumers

Hanzo IAM / cloud (`cek/cek.go`, per-principal encrypted stores):
`OpenDB(path, dek)` where `dek = UnwrapDEK(DeriveKey(masterKey, principal, id), blob, PrincipalAAD(principal, id))`.

## Versioning

PATCH bumps only. Current: **v0.3.1** — pure-Go backend now ENCRYPTS via the
vendored engine + hanzoai/sqlcipher codec VFS (was: `ErrEncryptionUnavailable`);
zero `modernc.org/*` modules; CGO backend migrated mattn/go-sqlite3 → hanzoai/csqlite.
