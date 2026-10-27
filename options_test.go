package sqlite

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"path/filepath"
	"testing"
)

func TestWithKey(t *testing.T) {
	passphrase := "test-passphrase-high-entropy-abc123"
	var c Config
	WithKey(passphrase)(&c)

	want := sha256.Sum256([]byte(passphrase))
	if !bytes.Equal(c.RawKey, want[:]) {
		t.Fatalf("WithKey: RawKey = %x, want SHA-256(%q) = %x", c.RawKey, passphrase, want[:])
	}
}

func TestWithRaft(t *testing.T) {
	peers := []string{"peer1:7001", "peer2:7002"}
	var c Config
	WithRaft("n1", ":7000", peers)(&c)

	if c.Mode != ModeRaft {
		t.Fatalf("WithRaft: Mode = %q, want %q", c.Mode, ModeRaft)
	}
	if c.NodeID != "n1" {
		t.Fatalf("WithRaft: NodeID = %q, want %q", c.NodeID, "n1")
	}
	if c.Listen != ":7000" {
		t.Fatalf("WithRaft: Listen = %q, want %q", c.Listen, ":7000")
	}
	if len(c.Peers) != len(peers) {
		t.Fatalf("WithRaft: len(Peers) = %d, want %d", len(c.Peers), len(peers))
	}
	for i, p := range peers {
		if c.Peers[i] != p {
			t.Fatalf("WithRaft: Peers[%d] = %q, want %q", i, c.Peers[i], p)
		}
	}
}

func TestWithCRDT(t *testing.T) {
	peers := []string{"peer1:8001", "peer2:8002", "peer3:8003"}
	var c Config
	WithCRDT("c1", ":8000", peers)(&c)

	if c.Mode != ModeCRDT {
		t.Fatalf("WithCRDT: Mode = %q, want %q", c.Mode, ModeCRDT)
	}
	if c.NodeID != "c1" {
		t.Fatalf("WithCRDT: NodeID = %q, want %q", c.NodeID, "c1")
	}
	if c.Listen != ":8000" {
		t.Fatalf("WithCRDT: Listen = %q, want %q", c.Listen, ":8000")
	}
	if len(c.Peers) != len(peers) {
		t.Fatalf("WithCRDT: len(Peers) = %d, want %d", len(c.Peers), len(peers))
	}
	for i, p := range peers {
		if c.Peers[i] != p {
			t.Fatalf("WithCRDT: Peers[%d] = %q, want %q", i, c.Peers[i], p)
		}
	}
}

func TestWithThreshold(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}

	var c Config
	WithThreshold(3, 5, priv)(&c)

	if c.Mode != ModeThreshold {
		t.Fatalf("WithThreshold: Mode = %q, want %q", c.Mode, ModeThreshold)
	}
	if c.Threshold != 3 {
		t.Fatalf("WithThreshold: Threshold = %d, want 3", c.Threshold)
	}
	if c.Parties != 5 {
		t.Fatalf("WithThreshold: Parties = %d, want 5", c.Parties)
	}
	if !bytes.Equal(c.SigningKey, priv) {
		t.Fatalf("WithThreshold: SigningKey mismatch")
	}
}

func TestWithPeers(t *testing.T) {
	peers := []string{"a:1", "b:2"}
	var c Config
	WithPeers(peers)(&c)

	if len(c.Peers) != len(peers) {
		t.Fatalf("WithPeers: len(Peers) = %d, want %d", len(c.Peers), len(peers))
	}
	for i, p := range peers {
		if c.Peers[i] != p {
			t.Fatalf("WithPeers: Peers[%d] = %q, want %q", i, c.Peers[i], p)
		}
	}
}

func TestWithPeersEmpty(t *testing.T) {
	var c Config
	WithPeers(nil)(&c)

	if c.Peers != nil {
		t.Fatalf("WithPeers(nil): Peers = %v, want nil", c.Peers)
	}
}

func TestEncryptedTrue(t *testing.T) {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i + 42)
	}

	dir := t.TempDir()
	dbPath := filepath.Join(dir, "encrypted.db")

	db, err := Open(dbPath, WithRawKey(key))
	if err != nil {
		t.Fatalf("Open with key: %v", err)
	}
	defer db.Close()

	if !db.Encrypted() {
		t.Fatal("Encrypted() = false for a keyed database, want true")
	}
}

func TestEncryptedFalse(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "plain.db")

	db, err := Open(dbPath)
	if err != nil {
		t.Fatalf("Open without key: %v", err)
	}
	defer db.Close()

	if db.Encrypted() {
		t.Fatal("Encrypted() = true for an unkeyed database, want false")
	}
}

// TestOptionComposition verifies that multiple options compose correctly,
// with later options overriding earlier ones where applicable.
func TestOptionComposition(t *testing.T) {
	peers1 := []string{"a:1"}
	peers2 := []string{"x:9", "y:10"}

	var c Config
	WithRaft("n1", ":7000", peers1)(&c)
	WithPeers(peers2)(&c)

	// Mode, NodeID, Listen from WithRaft should remain.
	if c.Mode != ModeRaft {
		t.Fatalf("composed: Mode = %q, want %q", c.Mode, ModeRaft)
	}
	if c.NodeID != "n1" {
		t.Fatalf("composed: NodeID = %q, want %q", c.NodeID, "n1")
	}
	if c.Listen != ":7000" {
		t.Fatalf("composed: Listen = %q, want %q", c.Listen, ":7000")
	}
	// Peers should be overridden by WithPeers.
	if len(c.Peers) != len(peers2) {
		t.Fatalf("composed: len(Peers) = %d, want %d", len(c.Peers), len(peers2))
	}
	for i, p := range peers2 {
		if c.Peers[i] != p {
			t.Fatalf("composed: Peers[%d] = %q, want %q", i, c.Peers[i], p)
		}
	}
}
