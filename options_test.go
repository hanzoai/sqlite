package sqlite

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"path/filepath"
	"reflect"
	"testing"
)

func TestWithKeyOption(t *testing.T) {
	var cfg1 Config
	WithKey("passphrase-alpha")(&cfg1)

	if len(cfg1.RawKey) != 32 {
		t.Fatalf("expected WithKey to produce 32-byte RawKey, got %d bytes", len(cfg1.RawKey))
	}

	var cfg2 Config
	WithKey("passphrase-alpha")(&cfg2)
	if !bytes.Equal(cfg1.RawKey, cfg2.RawKey) {
		t.Errorf("expected WithKey to be deterministic for the same passphrase")
	}

	var cfg3 Config
	WithKey("passphrase-beta")(&cfg3)
	if bytes.Equal(cfg1.RawKey, cfg3.RawKey) {
		t.Errorf("expected different passphrases to produce distinct RawKey values")
	}
}

func TestReplicationAndThresholdOptions(t *testing.T) {
	peers := []string{"10.0.0.1:7000", "10.0.0.2:7000"}

	var raftCfg Config
	WithRaft("node-raft-1", "0.0.0.0:7000", peers)(&raftCfg)
	if raftCfg.Mode != ModeRaft {
		t.Errorf("expected Mode=%q, got %q", ModeRaft, raftCfg.Mode)
	}
	if raftCfg.NodeID != "node-raft-1" || raftCfg.Listen != "0.0.0.0:7000" {
		t.Errorf("unexpected Raft NodeID/Listen: %+v", raftCfg)
	}
	if !reflect.DeepEqual(raftCfg.Peers, peers) {
		t.Errorf("expected Peers=%v, got %v", peers, raftCfg.Peers)
	}

	var crdtCfg Config
	WithCRDT("node-crdt-1", "0.0.0.0:8000", peers)(&crdtCfg)
	if crdtCfg.Mode != ModeCRDT {
		t.Errorf("expected Mode=%q, got %q", ModeCRDT, crdtCfg.Mode)
	}
	if crdtCfg.NodeID != "node-crdt-1" || crdtCfg.Listen != "0.0.0.0:8000" {
		t.Errorf("unexpected CRDT NodeID/Listen: %+v", crdtCfg)
	}
	if !reflect.DeepEqual(crdtCfg.Peers, peers) {
		t.Errorf("expected Peers=%v, got %v", peers, crdtCfg.Peers)
	}

	_, privKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate ed25519 key: %v", err)
	}

	var threshCfg Config
	WithThreshold(2, 3, privKey)(&threshCfg)
	if threshCfg.Mode != ModeThreshold {
		t.Errorf("expected Mode=%q, got %q", ModeThreshold, threshCfg.Mode)
	}
	if threshCfg.Threshold != 2 || threshCfg.Parties != 3 {
		t.Errorf("expected Threshold=2 Parties=3, got %d/%d", threshCfg.Threshold, threshCfg.Parties)
	}
	if !bytes.Equal(threshCfg.SigningKey, privKey) {
		t.Errorf("expected SigningKey to match provided ed25519.PrivateKey")
	}

	var peersCfg Config
	WithPeers(peers)(&peersCfg)
	if !reflect.DeepEqual(peersCfg.Peers, peers) {
		t.Errorf("expected WithPeers to set Peers=%v, got %v", peers, peersCfg.Peers)
	}
	if peersCfg.Mode != "" || peersCfg.NodeID != "" || peersCfg.Listen != "" ||
		peersCfg.Threshold != 0 || peersCfg.Parties != 0 || peersCfg.SigningKey != nil || peersCfg.RawKey != nil {
		t.Errorf("expected WithPeers not to mutate other Config fields, got %+v", peersCfg)
	}
}

func TestDBEncryptedReport(t *testing.T) {
	dir := t.TempDir()

	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatalf("rand.Read: %v", err)
	}

	encPath := filepath.Join(dir, "encrypted.db")
	encDB, err := Open(encPath, WithRawKey(key))
	if err != nil {
		t.Fatalf("Open encrypted DB failed: %v", err)
	}
	defer encDB.Close()

	if !encDB.Encrypted() {
		t.Errorf("expected Encrypted() to be true when opened with WithRawKey")
	}

	plainPath := filepath.Join(dir, "plain.db")
	plainDB, err := Open(plainPath)
	if err != nil {
		t.Fatalf("Open plain DB failed: %v", err)
	}
	defer plainDB.Close()

	if plainDB.Encrypted() {
		t.Errorf("expected Encrypted() to be false when opened without a key")
	}
}
