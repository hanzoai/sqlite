// Package sqlite provides an encrypted SQLite driver for Hanzo.
//
// Both backends encrypt at rest, in the SAME SQLCipher-4 on-disk format, and a
// database written by one opens under the other. The driver registers the
// database/sql driver name "sqlite" under BOTH build configurations, exposing the
// same public API either way:
//
//   - !CGO (//go:build !cgo) → the vendored pure-Go SQLite engine
//     (internal/engine) plus the hanzoai/sqlcipher codec VFS: page-level AES-256
//     encryption at rest, with NO cgo and NO external C library. This is what
//     CGO-off CI, tests, lint, and pure-Go deployments run. Nothing to link, no
//     amalgamation to build — it always encrypts.
//   - CGO  (//go:build cgo)  → hanzoai/csqlite + libsqlcipher: the same page-level
//     AES-256 format via the C codec, for builds that want the C engine's speed.
//     Build with:
//     CGO_ENABLED=1 \
//     CGO_CFLAGS="-DSQLITE_HAS_CODEC -DSQLITE_USE_URI=1 -I<sqlcipher>/include/sqlcipher" \
//     CGO_LDFLAGS="-lsqlcipher" \
//     go build -tags "libsqlite3 sqlite_fts5"
//     A cgo build that forgets to link libsqlcipher silently writes plaintext;
//     CodecLinked() proves the codec at runtime so such a build fails CI.
//
// Because the "sqlite" driver name is registered under both tags, any code doing
// `_ "github.com/hanzoai/sqlite"` + `sql.Open("sqlite", dsn)` (e.g. Hanzo IAM's
// xorm engine) compiles and runs encrypted under both — one import, one driver
// name, two backends, one format.
//
// The encryption key, replication mode, threshold config, and per-principal CEK
// derivation (cek.go, threshold.go) are pure Go and live in tag-neutral files;
// only the database/sql driver registration and the connect-time keying differ by
// build tag (driver_cgo.go / driver_nocgo.go).
package sqlite

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
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

// CodecLinked reports whether at-rest encryption is ACTUALLY working in this
// process — not merely advertised. EncryptionAvailable() is a backend-capability
// flag (true under both build tags), but a CGO build that forgot to link
// libsqlcipher silently writes PLAINTEXT. CodecLinked proves the codec at
// runtime: it opens a temp DB under a key, writes a marker, and checks the
// on-disk bytes are real ciphertext (no plaintext "SQLite format 3" header,
// marker absent).
//
// The pure-Go backend always returns true — its codec VFS is compiled in, nothing
// to mis-link. On the CGO backend it returns true only when libsqlcipher is
// actually linked. Use it to gate encryption assertions in tests: the pure-Go
// build and a correctly-linked CGO build run them; a CGO-without-codec build SKIPS
// instead of failing on plaintext (the Dockerfile build is the hard gate there).
func CodecLinked() bool {
	if !EncryptionAvailable() {
		return false
	}
	dir, err := os.MkdirTemp("", "sqlite-codec-probe-")
	if err != nil {
		return false
	}
	defer os.RemoveAll(dir)

	const marker = "codec-probe-marker-3f9c"
	path := filepath.Join(dir, "probe.db")
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i*3 + 5)
	}
	db, err := Open(path, WithRawKey(key))
	if err != nil {
		return false
	}
	if _, err := db.Exec(`CREATE TABLE p (v TEXT)`); err != nil {
		db.Close()
		return false
	}
	if _, err := db.Exec(`INSERT INTO p (v) VALUES (?)`, marker); err != nil {
		db.Close()
		return false
	}
	db.Close()

	raw, err := os.ReadFile(path)
	if err != nil {
		return false
	}
	if bytes.HasPrefix(raw, []byte("SQLite format 3\x00")) {
		return false // plaintext header => codec not linked
	}
	if bytes.Contains(raw, []byte(marker)) {
		return false // marker visible => not encrypted
	}
	return true
}

// Open opens an encrypted, optionally distributed SQLite database.
//
// A key (WithKey/WithRawKey/WithPrincipalKey) encrypts at rest under BOTH
// backends in the same SQLCipher-4 format: the pure-Go engine keys through the
// hanzoai/sqlcipher codec VFS, the CGO engine through libsqlcipher. A 32-byte
// key is required; EncryptionAvailable() is true either way, so the only reason
// Open rejects a key is a wrong length (never "no encryption on this backend").
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
		if !EncryptionAvailable() {
			return nil, ErrEncryptionUnavailable
		}
	}

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
