//go:build cgo

package sqlite

import (
	"database/sql"
	"errors"
	"fmt"
	"strings"

	sqlite3 "github.com/mattn/go-sqlite3"
)

// ErrEncryptionUnavailable is returned when an encryption key is supplied to a
// backend that cannot encrypt. Never returned by the CGO backend.
var ErrEncryptionUnavailable = errors.New("sqlite: encryption requested but this build has no SQLCipher backend (build with CGO_ENABLED=1 -tags libsqlite3 linked against libsqlcipher)")

// init registers the "sqlite" database/sql driver name — the same name
// modernc.org/sqlite registers under the !cgo backend — backed here by
// go-sqlite3 (CGO) linked against libsqlcipher. go-sqlite3 also registers
// "sqlite3" in its own init, so both names resolve to the same engine.
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
// mainline mattn/go-sqlite3 has NO `sqlcipher` build tag and no sqlite3_key()
// binding. It also CANNOT key a database from a ConnectHook: Open() runs a
// battery of PRAGMAs (busy_timeout, journal_mode, foreign_keys, ...) via
// sqlite3_exec BEFORE the ConnectHook fires, which touches the header of an
// existing encrypted file and fails with "file is not a database" on reopen.
//
// The working mechanism is SQLCipher's NATIVE URI key parameter: with
// SQLITE_USE_URI=1, a `file:PATH?...&key=x'HEX'` DSN is keyed by SQLCipher's VFS
// at sqlite3_open_v2 time — before mattn runs any pragma — so both create AND
// reopen succeed. The key therefore rides the DSN (see DSN below). Callers MUST
// keep that DSN out of logs (IAM sets showSql=false and never logs the DSN).
func init() {
	sql.Register("sqlite", &sqlite3.SQLiteDriver{})
}

// EncryptionAvailable reports that this build's backend can encrypt at rest.
//
// It returns true for the CGO backend, which is a BACKEND-capability flag, not a
// proof that libsqlcipher is actually linked: a CGO build WITHOUT the codec links
// plain sqlite and silently no-ops the key (writes plaintext). The production
// Dockerfile links libsqlcipher; the package's encryption-proof test verifies
// real ciphertext at runtime so a mis-linked build fails CI instead of shipping
// plaintext.
func EncryptionAvailable() bool { return true }

// OpenDB opens *path* as a database/sql DB on the CGO/SQLCipher backend with the
// given raw 256-bit key. It is the entry point for callers that need a *sql.DB
// (e.g. to hand to xorm.NewEngineWithDB). A nil key opens unencrypted. The
// returned DB is NOT pinged here; the caller (or Open) pings.
func OpenDB(path string, rawKey []byte) (*sql.DB, error) {
	return openDB(path, &Config{RawKey: rawKey})
}

// openDB opens the database on the mattn/SQLCipher backend using the SQLCipher
// URI key parameter (keyed at open time, reopen-safe).
func openDB(path string, cfg *Config) (*sql.DB, error) {
	db, err := sql.Open("sqlite", DSN(path, cfg.RawKey))
	if err != nil {
		return nil, fmt.Errorf("sqlite: open %s: %w", path, err)
	}
	return db, nil
}

// DSN builds a canonical IAM SQLite DSN for the active (CGO/mattn/SQLCipher)
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
func DSN(path string, rawKey []byte) string {
	params := []string{
		"_busy_timeout=10000",
		"_journal_mode=WAL",
		"_synchronous=NORMAL",
		"_foreign_keys=ON",
	}
	if rawKey != nil {
		// SQLCipher raw-key blob literal: x'..' => no passphrase KDF. Hex is
		// URL-safe so no escaping is needed; the single quotes are sub-delims,
		// legal in a URI query value.
		params = append(params, fmt.Sprintf("key=x'%x'", rawKey))
	}
	return fmt.Sprintf("file:%s?%s", path, strings.Join(params, "&"))
}
