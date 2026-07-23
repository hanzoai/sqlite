//go:build !cgo || sqlite_purego

package sqlite

import (
	"database/sql"
	"fmt"
	"net/url"
	"strings"

	// modernc.org/sqlite registers the "sqlite" database/sql driver in its own
	// init(). Blank-importing it here gives the pure-Go build a working "sqlite"
	// driver — the same driver name the cgo backend registers — so CGO-off CI,
	// lint, and local dev run without a C toolchain.
	//
	// A keyed store is NOT plaintext on this backend: openDB routes it through the
	// pure-Go SQLCipher codec envelope (envelope.go), which always encrypts and is
	// byte-compatible with the C libsqlcipher.
	_ "modernc.org/sqlite"
)

// CodecLinked reports whether the SQLCipher C codec is linked and encrypting. The
// pure-Go backend never links the C codec — encryption here is the pure-Go
// hanzoai/sqlcipher codec (via the envelope), not the C library — so it is always
// false. EncryptionAvailable is nonetheless true: a keyed store always encrypts.
// The name is retained for API symmetry with the cgo backend.
func CodecLinked() bool { return false }

// OpenDB opens *path* as a *sql.DB on the pure-Go backend. A non-nil key opens it
// at-rest-encrypted through the SQLCipher codec envelope (byte-compatible with C
// libsqlcipher); a nil key opens it unencrypted. Mirrors the cgo backend's
// signature so callers compile identically under both build tags.
func OpenDB(path string, rawKey []byte) (*sql.DB, error) {
	return openDB(path, &Config{RawKey: rawKey})
}

// openDB is the single funnel both Open and OpenDB pass through. A key routes to
// the pure-Go SQLCipher codec envelope, which ALWAYS encrypts — the pure-Go backend
// has no plaintext fallback for a keyed store. A nil key opens plaintext (the
// unencrypted dev/global/default engine).
func openDB(path string, cfg *Config) (*sql.DB, error) {
	if err := validKeyLen(cfg); err != nil {
		return nil, err
	}
	if cfg.RawKey != nil {
		return openEnvelope(path, cfg.RawKey)
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

// DSN builds an UNENCRYPTED modernc DSN for path (the `_pragma=NAME(VALUE)` form
// modernc actually applies). The encryption key never rides the pure-Go DSN — the
// codec envelope keys the file out of band — so a non-nil key here is a programming
// error and panics rather than emit a DSN that would open the database plaintext.
func DSN(path string, rawKey []byte) string {
	if rawKey != nil {
		panic("sqlite: DSN cannot carry a key on the pure-Go backend — the codec envelope keys the file; use OpenDB(path, key)")
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
