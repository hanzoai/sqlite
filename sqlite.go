// Package sqlite provides an at-rest-encrypted SQLite driver for Hanzo.
//
// ONE WAY, ALWAYS ENCRYPTED. A keyed store is encrypted on EVERY build — there is
// no build tag, environment switch, or missing C library under which it falls back
// to plaintext. EncryptionAvailable() is always true. The SQLCipher 4 page format
// is the single at-rest format, produced two byte-compatible ways:
//
//   - The pure-Go hanzoai/sqlcipher codec (the default, works everywhere): a keyed
//     open decrypts the file to a RAM-backed plaintext copy, the engine reads and
//     writes that copy, and Close/Checkpoint re-encrypts it to the real path
//     (envelope.go). This needs no C toolchain and no libsqlcipher, so native Go
//     (CGO_ENABLED=0) ALWAYS encrypts.
//   - The live libsqlcipher codec (an optional acceleration on cgo builds that link
//     it): page-level AES-256 keyed inside sqlite3_open_v2, with per-commit
//     durability. A cgo build links it with:
//     CGO_ENABLED=1 \
//     CGO_CFLAGS="-DSQLITE_HAS_CODEC -DSQLITE_USE_URI=1 -I<sqlcipher>/include/sqlcipher" \
//     CGO_LDFLAGS="-lsqlcipher" \
//     go build -tags "libsqlite3 sqlite_fts5"
//
// On a cgo build openDB uses the live codec when a runtime probe proves it encrypts
// (CodecLinked), and otherwise FALLS BACK to the pure-Go codec envelope — so a
// mis-linked libsqlcipher degrades to the pure-Go codec, never to plaintext. On the
// pure-Go build a key always routes to the envelope. Either way the file on disk is
// SQLCipher ciphertext, readable by the C library and by this package alike.
//
// The database/sql driver name "sqlite" is registered under both build tags
// (hanzoai/csqlite on cgo, modernc.org/sqlite on pure-Go), so any code doing
// `_ "github.com/hanzoai/sqlite"` + `sql.Open("sqlite", dsn)` compiles and runs on
// both — one import, one driver name, one encryption format.
//
// OPT-OUT BUILD TAG `sqlite_purego`: forces the pure-Go (modernc) backend even when
// CGO_ENABLED=1. It exists for one reason: a binary that links this fork AND another
// package importing modernc.org/sqlite directly would, under a plain CGO_ENABLED=1
// build, register the "sqlite" driver TWICE and panic at init. Such a service builds
// with `-tags sqlite_purego` so the whole binary registers "sqlite" exactly once.
// It does NOT change the encryption guarantee: the pure-Go backend also always
// encrypts a keyed store, via the same codec.
//
// The encryption key, replication mode, threshold config, and per-principal CEK
// derivation (cek.go, threshold.go) and the codec envelope (envelope.go) are pure
// Go and tag-neutral; only the driver registration and the DSN pragma syntax differ
// by build tag (driver_cgo.go / driver_nocgo.go).
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

}

// Option configures a database.
type Option func(*Config)

// WithKey derives the raw 256-bit page key from a passphrase with a SINGLE,
// UNSALTED SHA-256 — NOT a slow, salted KDF. It is therefore safe ONLY for a
// high-entropy passphrase (e.g. a base64-encoded random secret); a human-memorable
// passphrase is brute-forceable because there is no PBKDF2 stretching and no salt.
//
// A slow KDF is deliberately not applied here: the SQLCipher raw-key form takes the
// 32 bytes directly, and the file salt (which would seed a KDF) is not known when an
// Option is constructed. Production keys come from KMS already uniformly random —
// use WithRawKey / OpenDB(path, key) with those. For a low-entropy passphrase,
// derive a key out of band with a salted KDF (argon2id / PBKDF2) and pass it via
// WithRawKey.
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

// Encrypted reports whether this DB is encrypted at rest — true exactly when it was
// opened with a key. A keyed store always encrypts (EncryptionAvailable is always
// true), so the key alone decides it.
func (db *DB) Encrypted() bool {
	return db.config.RawKey != nil
}

// validKeyLen rejects a non-32-byte encryption key. It is enforced at the openDB
// funnel so BOTH the live-libsqlcipher path and the envelope path reject a wrong
// length: on the live path a non-32-byte `key=x'HEX'` URI blob would otherwise be
// reinterpreted by SQLCipher as a passphrase (a silent, different key), and OpenDB
// (unlike Open) applied no length check of its own.
func validKeyLen(cfg *Config) error {
	if cfg.RawKey != nil && len(cfg.RawKey) != 32 {
		return fmt.Errorf("sqlite: encryption key must be 32 bytes, got %d", len(cfg.RawKey))
	}
	return nil
}

// Open opens an at-rest-encrypted (when keyed), optionally distributed SQLite
// database. Passing an encryption key (WithKey/WithRawKey) always
// encrypts, on every build: the SQLCipher codec (live libsqlcipher when linked,
// otherwise the pure-Go codec envelope) keys the file. It never writes a keyed
// store as plaintext.
func Open(path string, opts ...Option) (*DB, error) {
	cfg := Config{Mode: ModeSingle}
	for _, o := range opts {
		o(&cfg)
	}
	// openDB is the single keyed-open funnel (both Open and OpenDB pass through it):
	// it validates the key length and routes a key to the SQLCipher codec, never to
	// a plaintext write.
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
