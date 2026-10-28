package sqlite

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"path/filepath"
	"reflect"
	"testing"
)

func TestWithKey(t *testing.T) {
	var cfg Config
	WithKey("first-passphrase")(&cfg)

	if len(cfg.RawKey) != 32 {
		t.Fatalf("expected RawKey length 32, got %d", len(cfg.RawKey))
	}
	expected := sha256.Sum256([]byte("first-passphrase"))
	if !bytes.Equal(cfg.RawKey, expected[:]) {
		t.Fatalf("RawKey does not match expected SHA-256 hash")
	}

	// Different passphrase should produce a different key.
	var cfg2 Config
	WithKey("second-passphrase")(&cfg2)
	if bytes.Equal(cfg.RawKey, cfg2.RawKey) {
		t.Fatalf("different passphrases produced identical keys")
	}
}

func TestWithRaft(t *testing.T) {
	peers := []string{"node2:7000", "node3:7000"}
	var cfg Config
	WithRaft("node1", "127.0.0.1:7000", peers)(&cfg)

	if cfg.Mode != ModeRaft {
		t.Fatalf("expected Mode %s, got %s", ModeRaft, cfg.Mode)
	}
	if cfg.NodeID != "node1" {
		t.Fatalf("expected NodeID %q, got %q", "node1", cfg.NodeID)
	}
	if cfg.Listen != "127.0.0.1:7000" {
		t.Fatalf("expected Listen %q, got %q", "127.0.0.1:7000", cfg.Listen)
	}
	if !reflect.DeepEqual(cfg.Peers, peers) {
		t.Fatalf("expected Peers %v, got %v", peers, cfg.Peers)
	}
}

func TestWithCRDT(t *testing.T) {
	peers := []string{"nodeA", "nodeB"}
	var cfg Config
	WithCRDT("my-node", "0.0.0.0:8000", peers)(&cfg)

	if cfg.Mode != ModeCRDT {
		t.Fatalf("expected Mode %s, got %s", ModeCRDT, cfg.Mode)
	}
	if cfg.NodeID != "my-node" {
		t.Fatalf("expected NodeID %q, got %q", "my-node", cfg.NodeID)
	}
	if cfg.Listen != "0.0.0.0:8000" {
		t.Fatalf("expected Listen %q, got %q", "0.0.0.0:8000", cfg.Listen)
	}
	if !reflect.DeepEqual(cfg.Peers, peers) {
		t.Fatalf("expected Peers %v, got %v", peers, cfg.Peers)
	}
}

func TestWithThreshold(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("failed to generate ed25519 key: %v", err)
	}
	_ = pub // not used directly, but generation ensures a valid key

	var cfg Config
	WithThreshold(3, 5, priv)(&cfg)

	if cfg.Mode != ModeThreshold {
		t.Fatalf("expected Mode %s, got %s", ModeThreshold, cfg.Mode)
	}
	if cfg.Threshold != 3 {
		t.Fatalf("expected Threshold 3, got %d", cfg.Threshold)
	}
	if cfg.Parties != 5 {
		t.Fatalf("expected Parties 5, got %d", cfg.Parties)
	}
	if !bytes.Equal(cfg.SigningKey, priv) {
		t.Fatalf("SigningKey not set correctly")
	}
}

func TestWithPeers(t *testing.T) {
	initialPeers := []string{"old1", "old2"}
	var cfg Config
	cfg.Mode = ModeRaft // set a non‑zero field to ensure it stays unchanged
	cfg.Peers = initialPeers

	newPeers := []string{"new1", "new2", "new3"}
	WithPeers(newPeers)(&cfg)

	if !reflect.DeepEqual(cfg.Peers, newPeers) {
		t.Fatalf("expected Peers %v, got %v", newPeers, cfg.Peers)
	}
	if cfg.Mode != ModeRaft {
		t.Fatalf("WithPeers altered Mode; expected %s, got %s", ModeRaft, cfg.Mode)
	}
}

func TestDBEncrypted(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "test.db")

	// Unencrypted DB
	dbPlain, err := Open(dbPath)
	if err != nil {
		t.Fatalf("failed to open unencrypted DB: %v", err)
	}
	if dbPlain.Encrypted() {
		t.Fatalf("expected unencrypted DB to report Encrypted() == false")
	}
	_ = dbPlain.Close()

	// Encrypted DB
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}
	dbEnc, err := Open(dbPath, WithRawKey(key))
	if err != nil {
		t.Fatalf("failed to open encrypted DB: %v", err)
	}
	if !dbEnc.Encrypted() {
		t.Fatalf("expected encrypted DB to report Encrypted() == true")
	}
	_ = dbEnc.Close()
}
