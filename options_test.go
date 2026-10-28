package sqlite

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"path/filepath"
	"reflect"
	"slices"
	"testing"
)

func TestOptionConstructors(t *testing.T) {
	t.Run("WithKey", func(t *testing.T) {
		passphrase := "high-entropy-test-passphrase-42"
		var c Config
		WithKey(passphrase)(&c)

		// 1. RawKey must be exactly 32 bytes
		if len(c.RawKey) != 32 {
			t.Fatalf("expected 32-byte key, got %d", len(c.RawKey))
		}

		// 2. RawKey must match SHA-256 of passphrase
		expected := sha256.Sum256([]byte(passphrase))
		if !bytes.Equal(c.RawKey, expected[:]) {
			t.Fatalf("RawKey mismatch: got %x, want %x", c.RawKey, expected[:])
		}

		// 3. Same passphrase must produce identical key
		var c2 Config
		WithKey(passphrase)(&c2)
		if !bytes.Equal(c.RawKey, c2.RawKey) {
			t.Fatalf("same passphrase produced different keys: %x vs %x", c.RawKey, c2.RawKey)
		}

		// 4. Different passphrase must produce distinct key
		var c3 Config
		WithKey("different-passphrase-99")(&c3)
		if bytes.Equal(c.RawKey, c3.RawKey) {
			t.Fatalf("different passphrases produced identical keys: %x", c.RawKey)
		}

		// 5. Must mutate only RawKey and leave other fields zero
		expectedCfg := Config{RawKey: expected[:]}
		if !reflect.DeepEqual(c, expectedCfg) {
			t.Fatalf("WithKey modified unrelated fields: got %+v, want %+v", c, expectedCfg)
		}
	})

	t.Run("WithRaft", func(t *testing.T) {
		var c Config
		nodeID := "node-raft-1"
		listen := "127.0.0.1:9001"
		peers := []string{"127.0.0.1:9002", "127.0.0.1:9003"}

		WithRaft(nodeID, listen, peers)(&c)

		if c.Mode != ModeRaft {
			t.Errorf("expected Mode %q, got %q", ModeRaft, c.Mode)
		}
		if c.NodeID != nodeID {
			t.Errorf("expected NodeID %q, got %q", nodeID, c.NodeID)
		}
		if c.Listen != listen {
			t.Errorf("expected Listen %q, got %q", listen, c.Listen)
		}
		if !slices.Equal(c.Peers, peers) {
			t.Errorf("expected Peers %v, got %v", peers, c.Peers)
		}

		expected := Config{
			Mode:   ModeRaft,
			NodeID: nodeID,
			Listen: listen,
			Peers:  peers,
		}
		if !reflect.DeepEqual(c, expected) {
			t.Fatalf("WithRaft set unexpected fields: got %+v, want %+v", c, expected)
		}
	})

	t.Run("WithCRDT", func(t *testing.T) {
		var c Config
		nodeID := "node-crdt-1"
		listen := "127.0.0.1:9101"
		peers := []string{"127.0.0.1:9102", "127.0.0.1:9103"}

		WithCRDT(nodeID, listen, peers)(&c)

		if c.Mode != ModeCRDT {
			t.Errorf("expected Mode %q, got %q", ModeCRDT, c.Mode)
		}
		if c.NodeID != nodeID {
			t.Errorf("expected NodeID %q, got %q", nodeID, c.NodeID)
		}
		if c.Listen != listen {
			t.Errorf("expected Listen %q, got %q", listen, c.Listen)
		}
		if !slices.Equal(c.Peers, peers) {
			t.Errorf("expected Peers %v, got %v", peers, c.Peers)
		}

		expected := Config{
			Mode:   ModeCRDT,
			NodeID: nodeID,
			Listen: listen,
			Peers:  peers,
		}
		if !reflect.DeepEqual(c, expected) {
			t.Fatalf("WithCRDT set unexpected fields: got %+v, want %+v", c, expected)
		}
	})

	t.Run("WithThreshold", func(t *testing.T) {
		var c Config
		pub, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatalf("ed25519.GenerateKey error: %v", err)
		}
		_ = pub
		threshold := 3
		parties := 5

		WithThreshold(threshold, parties, priv)(&c)

		if c.Mode != ModeThreshold {
			t.Errorf("expected Mode %q, got %q", ModeThreshold, c.Mode)
		}
		if c.Threshold != threshold {
			t.Errorf("expected Threshold %d, got %d", threshold, c.Threshold)
		}
		if c.Parties != parties {
			t.Errorf("expected Parties %d, got %d", parties, c.Parties)
		}
		if !bytes.Equal(c.SigningKey, priv) {
			t.Errorf("SigningKey mismatch: got %v, want %v", c.SigningKey, priv)
		}

		expected := Config{
			Mode:       ModeThreshold,
			Threshold:  threshold,
			Parties:    parties,
			SigningKey: priv,
		}
		if !reflect.DeepEqual(c, expected) {
			t.Fatalf("WithThreshold set unexpected fields: got %+v, want %+v", c, expected)
		}
	})

	t.Run("WithPeers", func(t *testing.T) {
		var c Config
		peers := []string{"10.0.0.1:8000", "10.0.0.2:8000"}

		WithPeers(peers)(&c)

		if !slices.Equal(c.Peers, peers) {
			t.Errorf("expected Peers %v, got %v", peers, c.Peers)
		}

		// Verify WithPeers changes ONLY Peers on a zero Config
		expected := Config{Peers: peers}
		if !reflect.DeepEqual(c, expected) {
			t.Fatalf("WithPeers modified fields other than Peers: got %+v, want %+v", c, expected)
		}
	})
}

func TestDBEncrypted(t *testing.T) {
	dir := t.TempDir()

	// 1. Unencrypted DB: Open without key options reports Encrypted() == false
	unencPath := filepath.Join(dir, "unencrypted.db")
	unencDB, err := Open(unencPath)
	if err != nil {
		t.Fatalf("Open unencrypted db: %v", err)
	}
	defer unencDB.Close()

	if unencDB.Encrypted() {
		t.Fatalf("expected Encrypted() == false for unkeyed database, got true")
	}

	// 2. Encrypted DB via WithRawKey: reports Encrypted() == true
	rawKey := make([]byte, 32)
	for i := range rawKey {
		rawKey[i] = byte(i*13 + 7)
	}
	rawKeyPath := filepath.Join(dir, "encrypted_raw.db")
	rawDB, err := Open(rawKeyPath, WithRawKey(rawKey))
	if err != nil {
		t.Fatalf("Open with WithRawKey: %v", err)
	}
	defer rawDB.Close()

	if !rawDB.Encrypted() {
		t.Fatalf("expected Encrypted() == true for WithRawKey database, got false")
	}

	// 3. Encrypted DB via WithKey: reports Encrypted() == true
	passKeyPath := filepath.Join(dir, "encrypted_pass.db")
	passDB, err := Open(passKeyPath, WithKey("high-entropy-random-passphrase-xyz-789"))
	if err != nil {
		t.Fatalf("Open with WithKey: %v", err)
	}
	defer passDB.Close()

	if !passDB.Encrypted() {
		t.Fatalf("expected Encrypted() == true for WithKey database, got false")
	}
}
