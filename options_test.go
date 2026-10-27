package sqlite

import (
	"bytes"
	"crypto/ed25519"
	"path/filepath"
	"reflect"
	"slices"
	"testing"
)

func TestOptionConstructors(t *testing.T) {
	peers := []string{"peer1:7001", "peer2:7002"}

	t.Run("WithRaft sets raft configuration", func(t *testing.T) {
		var c Config
		WithRaft("node-1", ":7000", peers)(&c)

		if c.Mode != ModeRaft {
			t.Errorf("expected Mode %v, got %v", ModeRaft, c.Mode)
		}
		if c.NodeID != "node-1" {
			t.Errorf("expected NodeID node-1, got %v", c.NodeID)
		}
		if c.Listen != ":7000" {
			t.Errorf("expected Listen :7000, got %v", c.Listen)
		}
		if !slices.Equal(c.Peers, peers) {
			t.Errorf("expected Peers %v, got %v", peers, c.Peers)
		}
	})

	t.Run("WithCRDT sets crdt configuration", func(t *testing.T) {
		var c Config
		WithCRDT("node-2", ":7002", peers)(&c)

		if c.Mode != ModeCRDT {
			t.Errorf("expected Mode %v, got %v", ModeCRDT, c.Mode)
		}
		if c.NodeID != "node-2" {
			t.Errorf("expected NodeID node-2, got %v", c.NodeID)
		}
		if c.Listen != ":7002" {
			t.Errorf("expected Listen :7002, got %v", c.Listen)
		}
		if !slices.Equal(c.Peers, peers) {
			t.Errorf("expected Peers %v, got %v", peers, c.Peers)
		}
	})

	t.Run("WithThreshold sets threshold configuration", func(t *testing.T) {
		pub, priv, err := ed25519.GenerateKey(nil)
		if err != nil {
			t.Fatalf("failed to generate ed25519 key: %v", err)
		}
		_ = pub

		var c Config
		WithThreshold(2, 3, priv)(&c)

		if c.Mode != ModeThreshold {
			t.Errorf("expected Mode %v, got %v", ModeThreshold, c.Mode)
		}
		if c.Threshold != 2 {
			t.Errorf("expected Threshold 2, got %v", c.Threshold)
		}
		if c.Parties != 3 {
			t.Errorf("expected Parties 3, got %v", c.Parties)
		}
		if !bytes.Equal(c.SigningKey, priv) {
			t.Errorf("expected SigningKey to match private key")
		}
	})

	t.Run("WithPeers changes only Peers", func(t *testing.T) {
		var c Config
		WithPeers(peers)(&c)

		if !slices.Equal(c.Peers, peers) {
			t.Errorf("expected Peers %v, got %v", peers, c.Peers)
		}

		expectedEmpty := Config{Peers: peers}
		if !reflect.DeepEqual(c, expectedEmpty) {
			t.Errorf("WithPeers modified other fields; got %+v, want %+v", c, expectedEmpty)
		}
	})

	t.Run("WithKey generates consistent 32-byte key", func(t *testing.T) {
		var c1, c2, c3 Config
		WithKey("super-secret-passphrase-1")(&c1)
		WithKey("super-secret-passphrase-1")(&c2)
		WithKey("different-passphrase-2")(&c3)

		if len(c1.RawKey) != 32 {
			t.Fatalf("expected 32-byte key, got %d bytes", len(c1.RawKey))
		}
		if !bytes.Equal(c1.RawKey, c2.RawKey) {
			t.Errorf("expected same key for identical passphrase, got %x vs %x", c1.RawKey, c2.RawKey)
		}
		if bytes.Equal(c1.RawKey, c3.RawKey) {
			t.Errorf("expected different key for different passphrase, got matching %x", c1.RawKey)
		}
	})
}

func TestDBEncrypted(t *testing.T) {
	tempDir := t.TempDir()

	unencPath := filepath.Join(tempDir, "unencrypted.db")
	unencDB, err := Open(unencPath)
	if err != nil {
		t.Fatalf("failed to open unencrypted db: %v", err)
	}
	defer unencDB.Close()

	if unencDB.Encrypted() {
		t.Errorf("expected unencDB.Encrypted() to be false, got true")
	}

	rawKey := bytes.Repeat([]byte{0x42}, 32)
	encPath := filepath.Join(tempDir, "encrypted.db")
	encDB, err := Open(encPath, WithRawKey(rawKey))
	if err != nil {
		t.Fatalf("failed to open encrypted db: %v", err)
	}
	defer encDB.Close()

	if !encDB.Encrypted() {
		t.Errorf("expected encDB.Encrypted() to be true, got false")
	}
}
