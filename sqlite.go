// Package sqlite provides an encrypted SQLite driver for Hanzo.
//
// It is dual-backend and registers the database/sql driver name "sqlite"
// under BOTH build configurations, exposing the same public API either way:
//
//   - CGO  (//go:build cgo && !sqlite_purego) → hanzoai/csqlite + SQLCipher:
//     page-level AES-256 encryption at rest. This is the production engine.
//     csqlite is the forked go-sqlite3 cgo bindings, vendored so nothing is
//     imported from mattn. Build with:
//     CGO_ENABLED=1 \
//     CGO_CFLAGS="-DSQLITE_HAS_CODEC -DSQLITE_USE_URI=1 -I<sqlcipher>/include/sqlcipher" \
//     CGO_LDFLAGS="-lsqlcipher" \
//     go build -tags "libsqlite3 sqlite_fts5"
//     NOTE: the `sqlcipher` tag is INERT in the go-sqlite3 lineage (ships
//     PLAINTEXT); the real recipe is the `libsqlite3` tag linked against
//     libsqlcipher with the codec + URI flags above.
//   - !CGO (//go:build !cgo || sqlite_purego) → modernc.org/sqlite (pure Go):
//     NO encryption. Used for CGO-off CI (test + lint) and local dev. Demanding
//     a key on this backend is a hard error — it never silently stores plaintext.
//
// OPT-OUT BUILD TAG `sqlite_purego`: forces the pure-Go (modernc) backend even
// when CGO_ENABLED=1. The default is unchanged (cgo → SQLCipher), so encryption
// consumers (Hanzo IAM's envelope-encrypted org DBs) are unaffected. The tag
// exists for one reason: a binary that links this fork AND another package that
// imports modernc.org/sqlite directly (e.g. a service embedding hanzoai/base,
// commerce, o11y, orm or tasks) would, under a plain CGO_ENABLED=1 build,
// register the database/sql "sqlite" driver TWICE — once here via csqlite, once
// by modernc — and panic at init ("sql: Register called twice for driver sqlite").
// Such a service that needs neither SQLCipher nor a C toolchain builds with
// `-tags sqlite_purego`: this fork then routes to modernc too, so the whole
// binary registers "sqlite" exactly once. (CGO_ENABLED=0 achieves the same and
// is what those services ship in prod; the tag is for CGO-on local dev / tests.)
//
// Because the "sqlite" driver name is registered under both tags, any code
// doing `_ "github.com/hanzoai/sqlite"` + `sql.Open("sqlite", dsn)` (e.g. Hanzo
// IAM's xorm engine) compiles and runs in CGO-off CI and runs encrypted in the
// CGO production build — one import, one driver name, two backends.
//
// The encryption key, replication mode, threshold config, and per-principal
// CEK derivation (cek.go, threshold.go) are pure Go and live in tag-neutral
// files; only the database/sql driver registration and the connect-time pragma
// application differ by build tag (driver_cgo.go / driver_nocgo.go).
package sqlite

import (
	"crypto/ed25519"
	"crypto/sha256"
	"database/sql"
	"fmt"
)

// Mode determines the replication strategy.
type Mode string

const (
	ModeSingle    Mode = "single"    // Local only
	ModeRaft      Mode = "raft"      // Strong consistency (leader writes)
	ModeCRDT      Mode = "crdt"      // Eventual consistency (all write)
	ModeThreshold Mode = "threshold" // t-of-n attestation for writes
)

// Config for opening a database.
type Config struct {
	// Encryption
	RawKey []byte // raw 256-bit key (skips KDF); nil means unencrypted

	// Replication
	Mode   Mode
	NodeID string
	Listen string   // bind address for replication
	Peers  []string // peer addresses

	// Threshold mode
	Threshold  int                // t value (signatures required)
	Parties    int                // n value (total parties)
	SigningKey ed25519.PrivateKey // this node's signing key

	// Internal: set by WithPrincipalKey if derivation fails.
	derivationErr error
}

// Option configures a database.
type Option func(*Config)

// WithKey derives a raw 256-bit key from a passphrase via SHA-256
// and configures sqlcipher to use it directly (skipping KDF).
func WithKey(passphrase string) Option {
	return func(c *Config) {
		h := sha256.Sum256([]byte(passphrase))
		c.RawKey = h[:]
	}
}

// WithRawKey sets a raw 256-bit encryption key (skips KDF).
func WithRawKey(key []byte) Option {
	return func(c *Config) { c.RawKey = key }
}

// WithRaft enables Raft consensus replication.
func WithRaft(nodeID, listen string, peers []string) Option {
	return func(c *Config) {
		c.Mode = ModeRaft
		c.NodeID = nodeID
		c.Listen = listen
		c.Peers = peers
	}
}

// WithCRDT enables CRDT eventual consistency replication.
func WithCRDT(nodeID, listen string, peers []string) Option {
	return func(c *Config) {
		c.Mode = ModeCRDT
		c.NodeID = nodeID
		c.Listen = listen
		c.Peers = peers
	}
}

// WithThreshold enables multi-party threshold attestation for writes.
func WithThreshold(t, n int, signingKey ed25519.PrivateKey) Option {
	return func(c *Config) {
		c.Mode = ModeThreshold
		c.Threshold = t
		c.Parties = n
		c.SigningKey = signingKey
	}
}

// WithPeers sets replication peers.
func WithPeers(peers []string) Option {
	return func(c *Config) { c.Peers = peers }
}

// DB wraps sql.DB with replication and encryption.
type DB struct {
	*sql.DB
	config Config
}

// Encrypted reports whether this DB is backed by an at-rest-encrypted engine.
func (db *DB) Encrypted() bool {
	return db.config.RawKey != nil && EncryptionAvailable()
}

// Open opens an encrypted, optionally distributed SQLite database.
//
// Under the !cgo backend, passing an encryption key (WithKey/WithRawKey/
// WithPrincipalKey) is a hard error: the pure-Go engine cannot encrypt and we
// refuse to silently persist plaintext when a caller asked for encryption.
func Open(path string, opts ...Option) (*DB, error) {
	cfg := Config{Mode: ModeSingle}
	for _, o := range opts {
		o(&cfg)
	}
	if cfg.derivationErr != nil {
		return nil, cfg.derivationErr
	}
	if cfg.RawKey != nil {
		if n := len(cfg.RawKey); n != 32 {
			return nil, fmt.Errorf("sqlite: encryption key must be 32 bytes, got %d", n)
		}
	}

	// openDB is the single keyed-open gate (both Open and OpenDB funnel through it):
	// a key on a build that cannot truly encrypt fails closed there with
	// ErrEncryptionUnavailable and creates no file — never a silent plaintext write.
	db, err := openDB(path, &cfg)
	if err != nil {
		return nil, err
	}

	if err := db.Ping(); err != nil {
		db.Close()
		return nil, fmt.Errorf("sqlite: ping %s: %w", path, err)
	}

	return &DB{DB: db, config: cfg}, nil
}
