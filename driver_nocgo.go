//go:build !cgo || sqlite_purego

package sqlite

import (
	"database/sql"
	"errors"
	"fmt"
	"net/url"
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
// this pure-Go backend, which cannot encrypt at rest. The remediation must NOT
// say `-tags sqlcipher` (that tag is inert in mainline mattn and ships
// plaintext) — the real recipe is the libsqlite3 tag linked against libsqlcipher.
var ErrEncryptionUnavailable = errors.New("sqlite: encryption requested but this build has no SQLCipher backend (build with CGO_ENABLED=1 -tags libsqlite3 linked against libsqlcipher)")

// EncryptionAvailable reports that this build CANNOT encrypt at rest (always
// false for the pure-Go backend). A keyed open therefore fails closed in openDB.
func EncryptionAvailable() bool { return false }

// CodecLinked reports whether the SQLCipher C codec is linked and encrypting. The
// pure-Go backend never links the C codec, so it is always false — the name is
// retained for API symmetry with the CGO backend (money/data consumers call it to
// guard a keyed open regardless of which backend the binary linked).
func CodecLinked() bool { return false }

// OpenDB opens *path* as a database/sql DB on the pure-Go backend. A non-nil key
// is a hard error: this backend cannot encrypt and must never silently persist
// plaintext when a caller asked for encryption. Mirrors the CGO backend's
// signature so callers compile identically under both build tags.
func OpenDB(path string, rawKey []byte) (*sql.DB, error) {
	return openDB(path, &Config{RawKey: rawKey})
}

// openDB opens the database on the pure-Go modernc backend. It is the single
// funnel BOTH Open and OpenDB pass through, so the keyed-open gate lives here: a
// configured key on a backend that cannot encrypt (EncryptionAvailable() == false)
// FAILS CLOSED with ErrEncryptionUnavailable and creates no file, so a keyed open
// never silently persists plaintext. Same predicate as the CGO backend's gate.
func openDB(path string, cfg *Config) (*sql.DB, error) {
	if cfg.RawKey != nil && !EncryptionAvailable() {
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
		"cache=shared",
	}
	// Escape the path so '?'/'#' in a path can't terminate it early and strip
	// query params (parity with the cgo backend; defense in depth).
	return fmt.Sprintf("file:%s?%s", escapeDBPath(path), strings.Join(params, "&"))
}

// escapeDBPath percent-encodes a filesystem path for safe embedding in a
// `file:PATH?query` DSN, preserving '/' but escaping '?' and '#'.
func escapeDBPath(path string) string {
	return strings.ReplaceAll(url.PathEscape(path), "%2F", "/")
}
