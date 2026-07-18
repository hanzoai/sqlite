//go:build !cgo

package sqlite

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"fmt"
	"net/url"
	"strings"

	// engine is Hanzo's vendored pure-Go SQLite engine; importing it runs its
	// init(), which registers the "sqlite" database/sql driver name — the same
	// name the CGO backend registers — so one import + sql.Open("sqlite", …)
	// works identically under both build tags.
	engine "github.com/hanzoai/sqlite/internal/engine"
	// vfs is the pure-Go SQLCipher codec VFS: it applies the hanzoai/sqlcipher
	// page format on every read/write, giving this CGO-free build REAL at-rest
	// encryption byte-compatible with C SQLCipher.
	"github.com/hanzoai/sqlite/internal/engine/vfs"
)

// ErrEncryptionUnavailable is retained for API symmetry with the CGO backend. It
// is never returned now: the pure-Go backend encrypts via the vendored engine +
// the hanzoai/sqlcipher codec VFS, so encryption is always available.
var ErrEncryptionUnavailable = errors.New("sqlite: encryption unavailable")

// EncryptionAvailable reports that this build can encrypt at rest. The pure-Go
// backend now encrypts through the hanzoai/sqlcipher codec VFS, so this is true
// under both build tags — there is no longer a plaintext-only backend.
func EncryptionAvailable() bool { return true }

// OpenDB opens *path* as a database/sql DB on the pure-Go backend with the given
// raw 256-bit key. A nil key opens unencrypted; a non-nil key opens through the
// SQLCipher codec VFS (real page-level AES-256 encryption at rest). Mirrors the
// CGO backend's signature so callers compile identically under both build tags.
func OpenDB(path string, rawKey []byte) (*sql.DB, error) {
	return openDB(path, &Config{RawKey: rawKey})
}

// openDB opens the database on the pure-Go engine. With a key it registers a
// per-database codec VFS and opens through it; the VFS is unregistered when the
// returned *sql.DB is closed (the connector implements io.Closer).
func openDB(path string, cfg *Config) (*sql.DB, error) {
	if cfg.RawKey == nil {
		db, err := sql.Open(driverName, DSN(path, nil))
		if err != nil {
			return nil, fmt.Errorf("sqlite: open %s: %w", path, err)
		}
		return db, nil
	}

	vfsName, closer, err := vfs.Register(cfg.RawKey)
	if err != nil {
		return nil, fmt.Errorf("sqlite: register codec vfs for %s: %w", path, err)
	}
	cc := &codecConnector{inner: engine.Connector(keyedDSN(path, vfsName)), closer: closer}
	db := sql.OpenDB(cc)
	// The codec VFS keeps the wal-index in per-database heap memory with no-op shm
	// locks, which is correct for exactly one connection. Cap the pool at one (also
	// how the encrypted stores are opened upstream). A keyed database is therefore
	// single-writer, single-process.
	db.SetMaxOpenConns(1)
	if err := ensureWAL(db); err != nil {
		db.Close()
		return nil, fmt.Errorf("sqlite: enable WAL on %s: %w", path, err)
	}
	return db, nil
}

// ensureWAL puts a keyed database into WAL mode. A new or DELETE-mode database is
// converted through an IN-MEMORY rollback journal (journal_mode=MEMORY), so the
// conversion — and the create-time writes before it — never place a plaintext page
// image on a -journal file on disk. The codec VFS therefore never has to encrypt a
// rollback journal, and refuses one outright (fail-closed). An already-WAL database
// is left as is (no WAL→MEMORY→WAL churn). The DELETE→WAL step must run on an
// established connection, not during the connection's own setup pragmas.
func ensureWAL(db *sql.DB) error {
	var mode string
	if err := db.QueryRow("PRAGMA journal_mode").Scan(&mode); err != nil {
		return err
	}
	if strings.EqualFold(mode, "wal") {
		return nil
	}
	if _, err := db.Exec("PRAGMA journal_mode=MEMORY"); err != nil {
		return err
	}
	if err := db.QueryRow("PRAGMA journal_mode=WAL").Scan(&mode); err != nil {
		return err
	}
	if !strings.EqualFold(mode, "wal") {
		return fmt.Errorf("journal_mode is %q, want wal", mode)
	}
	return nil
}

// codecConnector wraps the engine connector with the codec VFS's unregister
// closer. database/sql calls Close on a connector that implements io.Closer when
// its *sql.DB is closed, so the per-database VFS is torn down at exactly the right
// time — and the DEK it holds is wiped.
type codecConnector struct {
	inner  driver.Connector
	closer func() error
}

func (c *codecConnector) Connect(ctx context.Context) (driver.Conn, error) {
	return c.inner.Connect(ctx)
}
func (c *codecConnector) Driver() driver.Driver { return c.inner.Driver() }
func (c *codecConnector) Close() error          { return c.closer() }

// keyedDSN builds the DSN for an encrypted database: it selects the per-database
// codec VFS, declares the 80-byte SQLCipher reserve so page 1 is created with room
// for the IV+HMAC trailer, enables WAL (served by the codec VFS's in-process
// wal-index), and keeps temp storage in memory so no plaintext spill ever reaches
// disk.
func keyedDSN(path, vfsName string) string {
	params := []string{
		"vfs=" + vfsName,
		"_reserve_bytes=80",
		"_pragma=busy_timeout(10000)",
		"_pragma=synchronous(NORMAL)",
		"_pragma=temp_store(MEMORY)",
		"_pragma=foreign_keys(ON)",
	}
	return fmt.Sprintf("file:%s?%s", escapeDBPath(path), strings.Join(params, "&"))
}

// DSN builds a canonical IAM SQLite DSN for the pure-Go engine. It is only for the
// UNENCRYPTED path (rawKey == nil): the engine uses the `_pragma=NAME(VALUE)` query
// form. On the pure-Go backend the encryption key does NOT ride the DSN — it is
// bound to the codec VFS — so a non-nil key here is a programming error (use
// OpenDB), and DSN panics rather than emit a DSN that would silently open the
// database unencrypted.
func DSN(path string, rawKey []byte) string {
	if rawKey != nil {
		panic("sqlite: DSN cannot carry a key on the pure-Go backend — the key binds to the codec VFS; use OpenDB(path, key)")
	}
	params := []string{
		"_pragma=busy_timeout(10000)",
		"_pragma=journal_mode(WAL)",
		"_pragma=synchronous(NORMAL)",
		"_pragma=foreign_keys(ON)",
		"cache=shared",
	}
	return fmt.Sprintf("file:%s?%s", escapeDBPath(path), strings.Join(params, "&"))
}

// escapeDBPath percent-encodes a filesystem path for safe embedding in a
// `file:PATH?query` DSN, preserving '/' but escaping '?' and '#' so they cannot
// terminate the path early and strip query params.
func escapeDBPath(path string) string {
	return strings.ReplaceAll(url.PathEscape(path), "%2F", "/")
}
