//go:build cgo

package sqlite

import (
	"database/sql"
	"errors"
	"fmt"
	"net/url"
	"strings"

	csqlite "github.com/hanzoai/csqlite"
)

// ErrEncryptionUnavailable is retained for API symmetry with the pure-Go backend.
// It is never returned by the CGO backend, which encrypts through libsqlcipher.
var ErrEncryptionUnavailable = errors.New("sqlite: encryption unavailable")

// init registers the "sqlite" database/sql driver name — the same name the pure-Go
// backend registers under !cgo — backed here by Hanzo's csqlite (a self-contained
// cgo SQLite binding) linked against libsqlcipher. csqlite also registers "sqlite3"
// in its own init, so both names resolve to the same engine.
//
// HOW ENCRYPTION WORKS (read before changing anything):
//
// The production build links the SQLCipher codec:
//
//	CGO_ENABLED=1
//	-tags "libsqlite3 sqlite_fts5"          # link the SYSTEM sqlite, not the vendored amalgamation
//	CGO_CFLAGS="-DSQLITE_HAS_CODEC -DSQLITE_USE_URI=1 -I<sqlcipher>/include/sqlcipher"
//	CGO_LDFLAGS="-L<sqlcipher>/lib -lsqlcipher"
//
// csqlite keys a database through SQLCipher's NATIVE URI key parameter: with
// SQLITE_USE_URI=1, a `file:PATH?...&key=x'HEX'` DSN is keyed by SQLCipher's VFS
// at sqlite3_open_v2 time — before any connect-time pragma runs — so both create
// AND reopen succeed. The key therefore rides the DSN (see DSN below). Callers
// MUST keep that DSN out of logs (IAM sets showSql=false and never logs the DSN).
//
// Both backends write the SAME SQLCipher-4 on-disk format, so a database created
// by this CGO backend opens under the pure-Go backend (hanzoai/sqlite +
// hanzoai/sqlcipher) and vice versa.
func init() {
	sql.Register("sqlite", &csqlite.SQLiteDriver{})
}

// EncryptionAvailable reports that this build's backend can encrypt at rest.
//
// It returns true for the CGO backend, which is a BACKEND-capability flag, not a
// proof that libsqlcipher is actually linked: a CGO build WITHOUT the codec links
// plain sqlite and silently no-ops the key (writes plaintext). The production
// Dockerfile links libsqlcipher; the package's encryption-proof test verifies real
// ciphertext at runtime (CodecLinked) so a mis-linked build fails CI instead of
// shipping plaintext.
func EncryptionAvailable() bool { return true }

// OpenDB opens *path* as a database/sql DB on the CGO/SQLCipher backend with the
// given raw 256-bit key. It is the entry point for callers that need a *sql.DB
// (e.g. to hand to xorm.NewEngineWithDB). A nil key opens unencrypted. The
// returned DB is NOT pinged here; the caller (or Open) pings.
func OpenDB(path string, rawKey []byte) (*sql.DB, error) {
	return openDB(path, &Config{RawKey: rawKey})
}

// openDB opens the database on the csqlite/SQLCipher backend using the SQLCipher
// URI key parameter (keyed at open time, reopen-safe).
func openDB(path string, cfg *Config) (*sql.DB, error) {
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
// parameter, which SQLCipher applies inside sqlite3_open_v2 — before any pragma —
// making the connection reopen-safe. The DSN consequently CONTAINS the key;
// callers MUST NOT log it.
//
// rawKey must be exactly 32 bytes when non-nil (validated by Open; OpenDB trusts
// its caller). A nil key yields an unencrypted DSN for the global/dev/test engine.
//
// The path is percent-escaped (escapeDBPath): a path containing '?' or '#' would
// otherwise prematurely terminate the file portion of the DSN and DROP the
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
		// global/dev DSN). It is a SECURITY HAZARD on keyed databases: the shared
		// in-process page cache holds DECRYPTED pages, so a later connection opened
		// with the WRONG key reads cached plaintext instead of being rejected —
		// defeating per-key isolation. Never share the cache across an encrypted file.
		params = append(params, "cache=shared")
	}
	return fmt.Sprintf("file:%s?%s", escapeDBPath(path), strings.Join(params, "&"))
}

// escapeDBPath percent-encodes a filesystem path for safe embedding in the opaque
// portion of a `file:PATH?query` SQLite DSN. It preserves '/' (path separators stay
// readable) but escapes '?' and '#' (and any other reserved character) so they can
// never terminate the path early and strip query params.
func escapeDBPath(path string) string {
	// url.PathEscape escapes '?' and '#' but also escapes '/'; restore '/'.
	return strings.ReplaceAll(url.PathEscape(path), "%2F", "/")
}
