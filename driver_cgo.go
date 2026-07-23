//go:build cgo && !sqlite_purego

package sqlite

import (
	"database/sql"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"

	sqlite3 "github.com/hanzoai/csqlite"
)

// init registers the "sqlite" database/sql driver name — the same name
// modernc.org/sqlite registers under the !cgo backend — backed here by
// hanzoai/csqlite (the forked go-sqlite3 cgo bindings) linked against
// libsqlcipher. csqlite also registers "sqlite3" in its own init, so both names
// resolve to the same engine.
//
// HOW ENCRYPTION WORKS (read before changing anything):
//
// Real at-rest encryption requires the production build to:
//
//	CGO_ENABLED=1
//	-tags "libsqlite3 sqlite_fts5"          # link the SYSTEM sqlite, not the vendored amalgamation
//	CGO_CFLAGS="-DSQLITE_HAS_CODEC -DSQLITE_USE_URI=1 -I<sqlcipher>/include/sqlcipher"
//	CGO_LDFLAGS="-L<sqlcipher>/lib -lsqlcipher"
//
// the go-sqlite3 cgo bindings (csqlite) have NO `sqlcipher` build tag and no
// sqlite3_key() binding. They also CANNOT key a database from a ConnectHook:
// Open() runs a battery of PRAGMAs (busy_timeout, journal_mode, foreign_keys,
// ...) via sqlite3_exec BEFORE the ConnectHook fires, which touches the header
// of an existing encrypted file and fails with "file is not a database" on
// reopen.
//
// The working mechanism is SQLCipher's NATIVE URI key parameter: with
// SQLITE_USE_URI=1, a `file:PATH?...&key=x'HEX'` DSN is keyed by SQLCipher's VFS
// at sqlite3_open_v2 time — before csqlite runs any pragma — so both create AND
// reopen succeed. The key therefore rides the DSN (see DSN below). Callers MUST
// keep that DSN out of logs (IAM sets showSql=false and never logs the DSN).
func init() {
	sql.Register("sqlite", &sqlite3.SQLiteDriver{})
}

// CodecLinked reports whether the SQLCipher C codec is linked and ACTUALLY
// encrypting, proven by a cached one-time runtime probe — NOT a compile-time
// constant.
//
// The distinction is the whole point. A cgo build only has a live C codec if the
// SQLite it links is SQLCipher. A cgo build that links plain sqlite (the vendored
// amalgamation, or libsqlcipher absent) SILENTLY no-ops PRAGMA key and writes
// PLAINTEXT. A compile-time `return true` could not tell those apart, so it once
// reported the codec linked for a build that ships plaintext.
//
// This probes the linked engine at runtime (codecEncrypts): open a throwaway keyed
// database, write a sentinel, and confirm the bytes on disk are real ciphertext
// that round-trips under the key. The result is cached. When it is true, openDB
// uses the live libsqlcipher codec (per-commit durability); when it is FALSE, openDB
// falls back to the pure-Go SQLCipher codec envelope (envelope.go), which encrypts
// without libsqlcipher — so a keyed store is encrypted either way, never plaintext.
func CodecLinked() bool { return encryptionProbe() }

// probeOverride is a test-only seam (0 = use the real probe, 1 = force live-codec,
// 2 = force codec-broken). It lets the in-package tests exercise both openDB routes
// — live libsqlcipher and the pure-Go envelope fallback — without an actual
// plain-sqlite link. It is checked BEFORE the cached probe so a test override wins.
var probeOverride int32

var (
	probeOnce sync.Once
	probeVal  bool
)

// encryptionProbe returns the cached "is the C codec live" answer, honoring a test
// override first. codecEncrypts runs at most once.
func encryptionProbe() bool {
	switch atomic.LoadInt32(&probeOverride) {
	case 1:
		return true
	case 2:
		return false
	}
	probeOnce.Do(func() { probeVal = codecEncrypts() })
	return probeVal
}

// probeMarker is the sentinel row the capability probe writes; probeKey is a
// fixed, NON-secret key used only by the probe (the probe database is a throwaway
// in a temp dir, deleted immediately — no real data, no KMS key).
const probeMarker = "hanzo-sqlite-codec-probe-6b1f7d2a"

var probeKey = func() []byte {
	k := make([]byte, 32)
	for i := range k {
		k[i] = byte(i*3 + 5)
	}
	return k
}()

// codecEncrypts is the runtime measurement behind CodecLinked: it proves whether
// the linked C engine really encrypts. It opens a throwaway keyed database, writes
// a sentinel, and checks (a) the bytes on disk are ciphertext (no plaintext SQLite
// header, sentinel absent — encryptsAtRest) and (b) a keyed reopen reads the
// sentinel back. Any failure ⇒ false, and openDB then routes keyed opens to the
// pure-Go codec envelope instead of the live path — so a false result degrades to
// the pure-Go codec, it never degrades to plaintext.
//
// It opens through the RAW driver (sql.Open, not openDB) on purpose: openDB
// consults this measurement to choose its route, so routing the probe through it
// would recurse (openDB → CodecLinked → codecEncrypts → openDB). The probe is the
// one place a key reaches the live backend directly — it is measuring the codec's
// behaviour, not passing through the router.
func codecEncrypts() bool {
	dir, err := os.MkdirTemp("", "hanzo-sqlite-codec-probe-")
	if err != nil {
		return false
	}
	defer os.RemoveAll(dir)
	path := filepath.Join(dir, "probe.db")

	db, err := sql.Open("sqlite", DSN(path, probeKey))
	if err != nil {
		return false
	}
	if _, err := db.Exec(`CREATE TABLE p (v TEXT)`); err != nil {
		_ = db.Close()
		return false
	}
	if _, err := db.Exec(`INSERT INTO p (v) VALUES (?)`, probeMarker); err != nil {
		_ = db.Close()
		return false
	}
	if err := db.Close(); err != nil {
		return false
	}

	raw, err := os.ReadFile(path)
	if err != nil {
		return false
	}
	if !encryptsAtRest(raw, []byte(probeMarker)) {
		return false // plaintext on disk ⇒ codec not linked / not encrypting
	}

	// Reopen under the key and read the sentinel back: proves the ciphertext is
	// reproducibly keyed, not merely opaque (a keyed reopen must succeed).
	db2, err := sql.Open("sqlite", DSN(path, probeKey))
	if err != nil {
		return false
	}
	defer db2.Close()
	var got string
	if err := db2.QueryRow(`SELECT v FROM p`).Scan(&got); err != nil {
		return false
	}
	return got == probeMarker
}

// OpenDB opens *path* as a database/sql DB on the CGO/SQLCipher backend with the
// given raw 256-bit key. It is the entry point for callers that need a *sql.DB
// (e.g. to hand to xorm.NewEngineWithDB). A nil key opens unencrypted. The
// returned DB is NOT pinged here; the caller (or Open) pings.
func OpenDB(path string, rawKey []byte) (*sql.DB, error) {
	return openDB(path, &Config{RawKey: rawKey})
}

// openDB is the single funnel BOTH Open and OpenDB pass through, so the keyed-open
// route lives here. A keyed store is ALWAYS encrypted:
//
//   - CodecLinked() true  → the live libsqlcipher codec via the SQLCipher URI key
//     parameter (keyed inside sqlite3_open_v2, reopen-safe; per-commit durability).
//   - CodecLinked() false → the pure-Go SQLCipher codec envelope (envelope.go),
//     which encrypts without libsqlcipher. This is why a cgo build without a working
//     libsqlcipher still encrypts — it falls back to the pure-Go codec, never to
//     plaintext, and there is no dead end.
//
// A nil key opens unencrypted (the dev/global/default engine).
func openDB(path string, cfg *Config) (*sql.DB, error) {
	if err := validKeyLen(cfg); err != nil {
		return nil, err
	}
	if cfg.RawKey != nil && !CodecLinked() {
		return openEnvelope(path, cfg.RawKey)
	}
	db, err := sql.Open("sqlite", DSN(path, cfg.RawKey))
	if err != nil {
		return nil, fmt.Errorf("sqlite: open %s: %w", path, err)
	}
	return db, nil
}

// DSN builds a canonical IAM SQLite DSN for the active (CGO/csqlite/SQLCipher)
// backend.
//
// When rawKey is non-nil it is emitted as SQLCipher's native `key=x'HEX'` URI
// parameter, which SQLCipher applies inside sqlite3_open_v2 — before mattn's
// pragma battery — making the connection reopen-safe. The DSN consequently
// CONTAINS the key; callers MUST NOT log it.
//
// rawKey must be exactly 32 bytes when non-nil (validated by Open; OpenDB
// trusts its caller). A nil key yields an unencrypted DSN for the global/dev/test
// engine.
//
// The path is percent-escaped (escapeDBPath): a path containing '?' or '#'
// would otherwise prematurely terminate the file portion of the DSN and DROP the
// trailing query params — including `key=` — which would silently open the
// database UNENCRYPTED. Escaping makes that impossible regardless of caller input.
func DSN(path string, rawKey []byte) string {
	params := []string{
		"_busy_timeout=10000",
		"_journal_mode=WAL",
		"_synchronous=NORMAL",
		"_foreign_keys=ON",
	}
	if rawKey != nil {
		// SQLCipher raw-key blob literal: x'..' => no passphrase KDF. Hex is
		// URL-safe; the single quotes are sub-delims, legal in a URI query value.
		params = append(params, fmt.Sprintf("key=x'%x'", rawKey))
	} else {
		// cache=shared ONLY on the unencrypted path (parity with the legacy
		// global/dev DSN). It is a SECURITY HAZARD on keyed databases: the
		// shared in-process page cache holds DECRYPTED pages, so a later
		// connection opened with the WRONG key reads cached plaintext instead
		// of being rejected — defeating per-key isolation. Never share the
		// cache across an encrypted file.
		params = append(params, "cache=shared")
	}
	return fmt.Sprintf("file:%s?%s", escapeDBPath(path), strings.Join(params, "&"))
}

// escapeDBPath percent-encodes a filesystem path for safe embedding in the
// opaque portion of a `file:PATH?query` SQLite DSN. It preserves '/' (path
// separators stay readable) but escapes '?' and '#' (and any other reserved
// character) so they can never terminate the path early and strip query params.
func escapeDBPath(path string) string {
	// url.PathEscape escapes '?' and '#' but also escapes '/'; restore '/'.
	return strings.ReplaceAll(url.PathEscape(path), "%2F", "/")
}
