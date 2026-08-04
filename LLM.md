# sqlite

**Org:** hanzoai · **Ecosystem:** hanzo · **Path:** `/Users/a/work/hanzo/hanzoai/sqlite`
**Origin:** https://github.com/hanzoai/sqlite.git · **Module:** `github.com/hanzoai/sqlite`

Dual-backend `database/sql` driver. Registers the driver name **`sqlite`** under
BOTH build configs with one public API:

| Build | Backend | Encryption |
|-------|---------|------------|
| `CGO_ENABLED=1` + `-tags libsqlite3` + libsqlcipher | hanzoai/csqlite → SQLCipher | AES-256 at rest |
| `CGO_ENABLED=1` + `-tags sqlite_purego` | modernc.org/sqlite (pure Go) | none (fail-secure: keyed Open errors) |
| `CGO_ENABLED=0` | modernc.org/sqlite (pure Go) | none (fail-secure: keyed Open errors) |

The cgo backend is **`github.com/hanzoai/csqlite`** — the forked go-sqlite3 cgo
bindings, vendored so NOTHING is imported from `mattn/go-sqlite3` (it is absent
from go.mod/go.sum/dep graph). csqlite carries the SQLite amalgamation + cgo
driver and registers the `sqlite3` driver name; this wrapper registers `sqlite`
over the same `*csqlite.SQLiteDriver`. The `!cgo` path stays on
`modernc.org/sqlite` (a different, pure-Go engine — not go-sqlite3).

**`sqlite_purego` opt-out tag:** forces the pure-Go backend even under cgo. Default
(no tag) is unchanged — cgo → SQLCipher — so encryption consumers are untouched.
Use it when a binary links this fork AND another package that imports
`modernc.org/sqlite` directly (base/commerce/o11y/orm/tasks): a plain cgo build
would register `sqlite` twice (csqlite here + modernc there) and panic at init;
`-tags sqlite_purego` routes this fork to modernc too → one registration.

## File map (decomplected by what actually varies)

- `sqlite.go` — tag-neutral: `Config`, `Option`, `WithKey/WithRawKey/WithPrincipalKey/…`, `DB`, `Open()`, `EncryptionAvailable()`, `CodecLinked()` (runtime codec probe).
- `cek.go` — tag-neutral, pure Go: `DeriveKey` (HKDF-SHA256, length-prefixed injective info → KEK), `DeriveChildKey` (hierarchy), envelope `NewDEK`/`WrapDEK`/`UnwrapDEK` (AES-256-GCM; take a principal-binding `aad`), `PrincipalAAD` (the injective `(type,id)` encoding reused as the GCM AAD — DRY), `PrincipalGlobal/Org/User`.
- `threshold.go` — tag-neutral, pure Go: `ThresholdManager` (t-of-n Ed25519 write attestation).
- `driver_cgo.go` (`//go:build cgo && !sqlite_purego`) — registers `sqlite`→csqlite; `EncryptionAvailable()=true`; `OpenDB`/`DSN` emit SQLCipher URI key; path is percent-escaped so `?`/`#` can't strip `key=`.
- `driver_nocgo.go` (`//go:build !cgo || sqlite_purego`) — blank-imports modernc (self-registers `sqlite`); `EncryptionAvailable()=false`; keyed open → `ErrEncryptionUnavailable`. The `sqlite_purego` disjunct also selects this backend under cgo (see opt-out tag above).
- `hooks.go` — tag-neutral: `CommitHookFn` (`func() int32`), `HookRegisterer`. The ONE commit-hook API; `hooks_{cgo,nocgo}.go` (same `cgo && !sqlite_purego` / `!cgo || sqlite_purego` split as the drivers) supply `CommitHookRegisterer(driverConn any) (HookRegisterer, bool)` — csqlite's native `func() int` / modernc's `func() int32` bridged to `CommitHookFn`. Consumers import ONLY this pkg (Base's WAL/PITR replication uses it via `(*sql.Conn).Raw`).
- `pragma.go` — tag-neutral: `Pragma{Name,Value}`, `DefaultPragmas` (canonical embedded tuning: busy_timeout→WAL→…). `pragma_{cgo,nocgo}.go` supply `PragmaDSN(path, pragmas)` — csqlite `_name=value` / modernc `_pragma=name(value)`. One pragma set, correct on the active backend; a single-form DSN is silently dropped by the other backend.
- `encryption_proof_test.go` — anti-silent-plaintext gate (real ciphertext + reopen + wrong-key rejection under cgo, SKIPs if codec unlinked) + envelope rotation/injectivity/hierarchy proofs (run under both tags).
- `hooks_test.go` / `pragma_test.go` — prove (under BOTH tags) the commit hook fires + aborts + clears, and that `PragmaDSN` pragmas actually take effect (journal_mode=WAL, busy_timeout=10000, foreign_keys=ON).

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

the go-sqlite3 cgo bindings (now `hanzoai/csqlite`, forked verbatim) have **NO
`sqlcipher` build tag** and no `sqlite3_key` binding. `-tags sqlcipher` is
**inert → ships PLAINTEXT**. It also **cannot reopen** a SQLCipher DB from a
`ConnectHook` (csqlite runs `PRAGMA busy_timeout/journal_mode/…` before the hook
→ "file is not a database"). Proven dead ends. The working path:

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

Current: **v0.3.0**. v0.3.0 is the first MINOR bump — it changes the cgo backend
module (mattn → hanzoai/csqlite), a dependency-graph change, so not a patch.

- v0.3.0 — **Zero `mattn/go-sqlite3`.** The cgo backend is now
  `github.com/hanzoai/csqlite` (v0.1.0) — the go-sqlite3 cgo bindings forked
  verbatim into a Hanzo repo (SQLite amalgamation + cgo driver + callback
  trampolines, rebranded `package csqlite`, MIT preserved). `driver_cgo.go`,
  `hooks_cgo.go`, `errcodes_cgo.go`, `filecontrol_cgo.go` import
  `sqlite3 "github.com/hanzoai/csqlite"` (alias kept, so the wrapper code is
  otherwise unchanged). go.mod drops `require mattn/go-sqlite3`, adds
  `require hanzoai/csqlite`; `mattn/go-sqlite3` is absent from go.mod/go.sum and
  every dep graph (cgo, `!cgo`, `libsqlite3`). This lets consumers
  (cloud/o11y/ai/base/commerce) delete the
  `replace mattn/go-sqlite3 v2.0.3+incompatible => v1.14.47` redirect. SQLCipher
  is unchanged (same `-tags libsqlite3` + libsqlcipher recipe, same URI key);
  proven green: `SQLITE_REQUIRE_CODEC=1 TestEncryptionProof` PASSES through the
  fork, `cek_golden` fixture still decrypts, all three build configs green. The
  `!cgo` path stays on `modernc.org/sqlite` (a distinct pure-Go engine, not
  go-sqlite3, so out of scope for the mattn rip).
- v0.2.3 — Two backend-neutral primitives that let hanzoai/replicate drop its
  direct modernc import (the last second `sql.Register("sqlite")` in the cgo
  cloud binary — base→commerce→cloud all embed replicate, so this was a live
  `Register called twice` panic under CGO=1):
  - `SetPersistWAL(rawConn any, on bool) error` (`filecontrol_{cgo,nocgo}.go`):
    sets SQLITE_FCNTL_PERSIST_WAL on a raw driver conn (from (*sql.Conn).Raw) —
    mattn `SetFileControlInt("main", SQLITE_FCNTL_PERSIST_WAL, …)` under cgo,
    modernc's exported `FileControl.FileControlPersistWAL` otherwise. Keeps the
    -wal file across the last close, which WAL-shipping replication requires.
  - `OpenPragma(dsn string, pragmas []Pragma) (*sql.DB, error)` (`connector.go`):
    a database/sql Connector that applies pragmas to EVERY pooled connection via
    PRAGMA at connect time. The load-bearing case is wal_autocheckpoint: modernc
    honors `?_pragma=wal_autocheckpoint(0)` in the DSN, but mattn silently DROPS
    it, so a CGO=1 binary would re-enable auto-checkpoint and truncate the WAL
    under a replicator — losing committed frames. Running it per-connection via
    ExecContext is backend-neutral. Proven on 3 concurrent conns under both
    backends. Tag-neutral (resolves the registered "sqlite" driver via a
    throwaway :memory: DB).
- v0.2.2 — Two additions that let the remaining direct-modernc consumers drop
  their backend import, plus the luxfi-crypto AEAD swap:
  - `IsConstraintUnique` / `IsConstraintPrimaryKey` / `IsConstraintForeignKey`
    (`errcodes.go` + backend-split `errcodes_{cgo,nocgo}.go`): backend-neutral
    classification of SQLite constraint violations. The three predicates live
    once (tag-neutral); only the error unwrap (mattn `sqlite3.Error` value /
    modernc `*sqlite.Error` pointer) and the reference constants vary by tag —
    same `cgo && !sqlite_purego` / `!cgo || sqlite_purego` scheme as the driver.
    First consumer: o11y's `sqlitesqlstore`, which drops
    `err.(*modernc.Error).Code() == lib.SQLITE_CONSTRAINT_*`.
  - `cek.go` AES-256-GCM DEK wrap/unwrap moved from stdlib crypto/aes+cipher to
    `github.com/luxfi/crypto/aead.NewAES256GCM` (luxfi wraps crypto/aes +
    cipher.NewGCM → standard NIST AES-256-GCM, byte-identical: 12-byte nonce,
    16-byte tag, 61-byte sidecar unchanged, DEK never regenerated). The KEK
    stays on `x/crypto/hkdf` (RFC-5869) — luxfi/crypto/kdf is a QZMQ KeySchedule
    with hard-coded labels, NOT generic HKDF, so repointing it would rederive
    every KEK and brick all encrypted stores. Regression gate: `cek_golden_test.go`
    pins a FROZEN pre-swap sidecar fixture and asserts post-swap UnwrapDEK
    decrypts it to the exact DEK, green under all backends. luxfi/crypto v1.19.26.
- v0.2.1 — Unified commit-hook + pragma-DSN surface (`hooks*.go`, `pragma*.go`)
  so consumers import ONLY `hanzoai/sqlite` and drop every direct
  `modernc.org/sqlite` import. `CommitHookRegisterer` bridges mattn `func() int`
  / modernc `func() int32` to one `CommitHookFn`; `PragmaDSN`/`DefaultPragmas`
  encode one pragma set in the active backend's DSN syntax. First consumer:
  hanzoai/base (v1.5.5) routes `core.DefaultDBConnect`, the multitenant `store`,
  and its WAL/PITR commit hook onto this — zero direct modernc imports remain, so
  a cgo consumer that needs SQLCipher (commerce's per-tenant money DBs) no longer
  double-registers "sqlite". Complements the v0.1.5 `sqlite_purego` opt-out (which
  serves the OTHER case: a pure-Go cgo consumer that wants neither SQLCipher nor
  to drop modernc). The four backend-split files share the drivers' exact build
  constraints, so all four tag/cgo combos stay mutually exclusive + exhaustive.
- v0.1.5 — `sqlite_purego` opt-out build tag: `//go:build cgo && !sqlite_purego`
  (mattn/SQLCipher, default) vs `//go:build !cgo || sqlite_purego` (modernc). Lets
  a binary that also links a direct `modernc.org/sqlite` importer build under
  CGO_ENABLED=1 without a double `sql.Register("sqlite")` panic. Default cgo
  behavior unchanged (SQLCipher), so encryption consumers are untouched.
- v0.1.4 — `WrapDEK`/`UnwrapDEK` take a principal-binding GCM `aad` + add
  `PrincipalAAD` (defense-in-depth). Dockerfile fixed to link the codec and
  self-assert via `SQLITE_REQUIRE_CODEC=1` (was inert-tag CI-theater).

## Licensing

`MIT OR Apache-2.0`, at your option — per HIP-0137 (`hanzoai/hips`, `HIPs/hip-0137-one-license.md`). Relicensed from BSD-3-Clause,
which HIP-0137 puts out of scope for `hanzoai`.

Scope is **this branch's tree only**. This package is a driver *shim*: the
SQLite amalgamation and the cgo bindings live in their own upstreams
(`hanzoai/csqlite`, `modernc.org/sqlite`) under their own licences and are not
vendored here — which is what makes the relicense clean. Non-default branches
that *do* vendor generated `internal/` sources carrying third-party headers are
outside this change; the `LICENSE` files here speak for the tree they sit in and
make no claim over those.
