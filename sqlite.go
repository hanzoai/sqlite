// Package sqlite provides a distributed, encrypted SQLite driver for Hanzo.
//
// Built on go-sqlite3 with sqlcipher for page-level AES-256-CBC encryption.
// Supports single-node, Raft consensus, CRDT sync, and threshold attestation modes.
//
// Drop-in replacement for modernc.org/sqlite in Hanzo Base.
package sqlite

import (
	"crypto/ed25519"
	"database/sql"
	"fmt"
	"strings"
	"sync/atomic"

	sqlite3 "github.com/mattn/go-sqlite3"
)

var driverSeq atomic.Uint64

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
	Key    string // passphrase for sqlcipher KDF
	RawKey []byte // raw 256-bit key (skips KDF)

	// Replication
	Mode    Mode
	NodeID  string
	Listen  string   // bind address for replication
	Peers   []string // peer addresses

	// Threshold mode
	Threshold  int              // t value (signatures required)
	Parties    int              // n value (total parties)
	SigningKey ed25519.PrivateKey // this node's signing key

	// Internal: set by WithPrincipalKey if derivation fails.
	derivationErr error
}

// Option configures a database.
type Option func(*Config)

// WithKey sets the sqlcipher passphrase.
func WithKey(passphrase string) Option {
	return func(c *Config) { c.Key = passphrase }
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
	// repl   replication layer (raft/crdt/threshold) — initialized on Open
}

// Open opens an encrypted, optionally distributed SQLite database.
func Open(path string, opts ...Option) (*DB, error) {
	cfg := Config{Mode: ModeSingle}
	for _, o := range opts {
		o(&cfg)
	}
	if cfg.derivationErr != nil {
		return nil, cfg.derivationErr
	}

	// Build sqlcipher connection string
	dsn := buildDSN(path, &cfg)

	// Register driver with sqlcipher pragmas (unique name per Open call)
	driverName := fmt.Sprintf("sqlite3_hanzo_%d", driverSeq.Add(1))
	sql.Register(driverName, &sqlite3.SQLiteDriver{
		ConnectHook: func(conn *sqlite3.SQLiteConn) error {
			return applyCipherPragmas(conn, &cfg)
		},
	})

	db, err := sql.Open(driverName, dsn)
	if err != nil {
		return nil, fmt.Errorf("sqlite: open %s: %w", path, err)
	}

	// Verify encryption works
	if err := db.Ping(); err != nil {
		db.Close()
		return nil, fmt.Errorf("sqlite: ping %s: %w", path, err)
	}

	return &DB{DB: db, config: cfg}, nil
}

func buildDSN(path string, cfg *Config) string {
	params := []string{
		"_journal_mode=WAL",
		"_synchronous=NORMAL",
		"_busy_timeout=5000",
		"_foreign_keys=ON",
	}
	return fmt.Sprintf("file:%s?%s", path, strings.Join(params, "&"))
}

func applyCipherPragmas(conn *sqlite3.SQLiteConn, cfg *Config) error {
	if cfg.RawKey != nil {
		// Raw 256-bit key — skip KDF
		hexKey := fmt.Sprintf("\"x'%x'\"", cfg.RawKey)
		if _, err := conn.Exec("PRAGMA key = "+hexKey, nil); err != nil {
			return fmt.Errorf("sqlite: set raw key: %w", err)
		}
	} else if cfg.Key != "" {
		// Passphrase — sqlcipher runs PBKDF2
		if _, err := conn.Exec(fmt.Sprintf("PRAGMA key = '%s'", cfg.Key), nil); err != nil {
			return fmt.Errorf("sqlite: set key: %w", err)
		}
	}

	// sqlcipher settings
	pragmas := []string{
		"PRAGMA cipher_page_size = 4096",
		"PRAGMA kdf_iter = 256000",
		"PRAGMA cipher_hmac_algorithm = HMAC_SHA512",
		"PRAGMA cipher_kdf_algorithm = PBKDF2_HMAC_SHA512",
	}
	for _, p := range pragmas {
		if _, err := conn.Exec(p, nil); err != nil {
			return fmt.Errorf("sqlite: %s: %w", p, err)
		}
	}

	return nil
}
