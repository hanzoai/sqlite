package sqlite

import (
	"bytes"
	"crypto/ed25519"
	"path/filepath"
	"reflect"
	"slices"
	"testing"
)

func TestWithKey(t *testing.T) {
	var c Config
	passphrase := "super-secret-passphrase"
	WithKey(passphrase)(&c)

	if len(c.RawKey) != 32 {
		t.Fatalf("expected 32-byte key, got %d bytes", len(c.RawKey))
	}

	var c2 Config
	WithKey(passphrase)(&c2)
	if !bytes.Equal(c.RawKey, c2.RawKey) {
		t.Fatalf("expected same key for same passphrase, got %x vs %x", c.RawKey, c2.RawKey)
	}

	var c3 Config
	WithKey("different-passphrase")(&c3)
	if bytes.Equal(c.RawKey, c3.RawKey) {
		t.Fatalf("expected different key for different passphrase, got %x", c.RawKey)
	}

	expected := Config{RawKey: c.RawKey}
	if !reflect.DeepEqual(c, expected) {
		t.Fatalf("WithKey modified extra fields: got %+v, want %+v", c, expected)
	}
}

func TestWithRaft(t *testing.T) {
	var c Config
	peers := []string{"10.0.0.2:7000", "10.0.0.3:7000"}
	WithRaft("n1", ":7000", peers)(&c)

	if c.Mode != ModeRaft {
		t.Errorf("Mode = %v, want %v", c.Mode, ModeRaft)
	}
	if c.NodeID != "n1" {
		t.Errorf("NodeID = %q, want %q", c.NodeID, "n1")
	}
	if c.Listen != ":7000" {
		t.Errorf("Listen = %q, want %q", c.Listen, ":7000")
	}
	if !slices.Equal(c.Peers, peers) {
		t.Errorf("Peers = %v, want %v", c.Peers, peers)
	}

	expected := Config{
		Mode:   ModeRaft,
		NodeID: "n1",
		Listen: ":7000",
		Peers:  peers,
	}
	if !reflect.DeepEqual(c, expected) {
		t.Fatalf("WithRaft modified extra fields: got %+v, want %+v", c, expected)
	}
}

func TestWithCRDT(t *testing.T) {
	var c Config
	peers := []string{"10.0.0.2:7001", "10.0.0.3:7001"}
	WithCRDT("n2", ":7001", peers)(&c)

	if c.Mode != ModeCRDT {
		t.Errorf("Mode = %v, want %v", c.Mode, ModeCRDT)
	}
	if c.NodeID != "n2" {
		t.Errorf("NodeID = %q, want %q", c.NodeID, "n2")
	}
	if c.Listen != ":7001" {
		t.Errorf("Listen = %q, want %q", c.Listen, ":7001")
	}
	if !slices.Equal(c.Peers, peers) {
		t.Errorf("Peers = %v, want %v", c.Peers, peers)
	}

	expected := Config{
		Mode:   ModeCRDT,
		NodeID: "n2",
		Listen: ":7001",
		Peers:  peers,
	}
	if !reflect.DeepEqual(c, expected) {
		t.Fatalf("WithCRDT modified extra fields: got %+v, want %+v", c, expected)
	}
}

func TestWithThreshold(t *testing.T) {
	var c Config
	_, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}

	WithThreshold(2, 3, priv)(&c)

	if c.Mode != ModeThreshold {
		t.Errorf("Mode = %v, want %v", c.Mode, ModeThreshold)
	}
	if c.Threshold != 2 {
		t.Errorf("Threshold = %d, want 2", c.Threshold)
	}
	if c.Parties != 3 {
		t.Errorf("Parties = %d, want 3", c.Parties)
	}
	if !bytes.Equal(c.SigningKey, priv) {
		t.Errorf("SigningKey = %x, want %x", c.SigningKey, priv)
	}

	expected := Config{
		Mode:       ModeThreshold,
		Threshold:  2,
		Parties:    3,
		SigningKey: priv,
	}
	if !reflect.DeepEqual(c, expected) {
		t.Fatalf("WithThreshold modified extra fields: got %+v, want %+v", c, expected)
	}
}

func TestWithPeers(t *testing.T) {
	var c Config
	peers := []string{"peer1:5000", "peer2:5000"}
	WithPeers(peers)(&c)

	if !slices.Equal(c.Peers, peers) {
		t.Errorf("Peers = %v, want %v", c.Peers, peers)
	}

	expected := Config{Peers: peers}
	if !reflect.DeepEqual(c, expected) {
		t.Fatalf("WithPeers modified extra fields: got %+v, want %+v", c, expected)
	}

	prefilled := Config{
		Mode:      ModeRaft,
		NodeID:    "node-xyz",
		Listen:    ":8080",
		Threshold: 1,
		Parties:   2,
	}
	updated := prefilled
	WithPeers(peers)(&updated)
	prefilled.Peers = peers
	if !reflect.DeepEqual(updated, prefilled) {
		t.Fatalf("WithPeers modified fields other than Peers: got %+v, want %+v", updated, prefilled)
	}
}

func TestDBEncrypted(t *testing.T) {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i + 1)
	}

	tempDir := t.TempDir()

	// Keyed database: Encrypted() must report true.
	encPath := filepath.Join(tempDir, "encrypted.db")
	encDB, err := Open(encPath, WithRawKey(key))
	if err != nil {
		t.Fatalf("Open encrypted: %v", err)
	}
	defer encDB.Close()

	if !encDB.Encrypted() {
		t.Errorf("encDB.Encrypted() = false, want true")
	}

	// Plain database: Encrypted() must report false.
	plainPath := filepath.Join(tempDir, "plain.db")
	plainDB, err := Open(plainPath)
	if err != nil {
		t.Fatalf("Open plain: %v", err)
	}
	defer plainDB.Close()

	if plainDB.Encrypted() {
		t.Errorf("plainDB.Encrypted() = true, want false")
	}
}
