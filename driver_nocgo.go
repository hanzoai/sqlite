//go:build !cgo

package sqlite

import (
	"database/sql"
	"errors"
	"fmt"
	"strings"

	// modernc.org/sqlite registers the "sqlite" database/sql driver in its own
	// init(). Blank-importing it here gives the !cgo build a working pure-Go
	// "sqlite" driver — the same driver name the CGO backend registers — so
	// CGO-off CI (tests + lint) and local dev run without a C toolchain.
	//
	// NOTE: this backend does NOT encrypt. Open() rejects any encryption key
	// before reaching openDB, so plaintext is never silently written when a
	// caller asked for encryption.
	_ "modernc.org/sqlite"
)

// ErrEncryptionUnavailable is returned when an encryption key is supplied to
// this pure-Go backend, which cannot encrypt at rest.
var ErrEncryptionUnavailable = errors.New("sqlite: encryption requested but this build has no SQLCipher backend (build with CGO_ENABLED=1 -tags sqlcipher)")

// EncryptionAvailable reports that this build CANNOT encrypt at rest (always
// false for the pure-Go backend).
func EncryptionAvailable() bool { return false }

// OpenDB opens *path* as a database/sql DB on the pure-Go backend. A non-nil key
// is a hard error: this backend cannot encrypt and must never silently persist
// plaintext when a caller asked for encryption. Mirrors the CGO backend's
// signature so callers compile identically under both build tags.
func OpenDB(path string, rawKey []byte) (*sql.DB, error) {
	return openDB(path, &Config{RawKey: rawKey})
}

// openDB opens the database on the pure-Go modernc backend. A configured key is
// a programming error here: Open() returns ErrEncryptionUnavailable before this
// is reached, but we defend the invariant at the boundary too.
func openDB(path string, cfg *Config) (*sql.DB, error) {
	if cfg.RawKey != nil {
		return nil, ErrEncryptionUnavailable
	}
	db, err := sql.Open("sqlite", buildDSN(path, cfg))
	if err != nil {
		return nil, fmt.Errorf("sqlite: open %s: %w", path, err)
	}
	return db, nil
}

func buildDSN(path string, cfg *Config) string {
	return DSN(path, nil)
}

// DSN builds a canonical IAM SQLite DSN for the active (pure-Go modernc)
// backend. modernc uses the `_pragma=NAME(VALUE)` query form; the mattn-style
// `_busy_timeout=N` params it silently IGNORES, so emitting the correct form
// here is what actually applies WAL + busy_timeout on the !cgo path.
//
// rawKey MUST be nil — the pure-Go backend cannot encrypt. A non-nil key
// triggers a panic rather than emitting a plaintext DSN, because reaching here
// with a key means an upstream encryption guard was bypassed.
func DSN(path string, rawKey []byte) string {
	if rawKey != nil {
		panic("sqlite: DSN called with a key on the pure-Go backend — encryption is unavailable without CGO+SQLCipher")
	}
	params := []string{
		"_pragma=busy_timeout(10000)",
		"_pragma=journal_mode(WAL)",
		"_pragma=synchronous(NORMAL)",
		"_pragma=foreign_keys(ON)",
	}
	return fmt.Sprintf("file:%s?%s", path, strings.Join(params, "&"))
}
