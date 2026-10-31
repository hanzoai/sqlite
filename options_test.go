package sqlite

import (
	"crypto/ed25519"
	"crypto/rand"
	"path/filepath"
	"reflect"
	"testing"
)

// TestWithKeyDerivesStable32ByteKey pins WithKey: SHA-256 of the passphrase,
// stable for the same input and distinct for different inputs.
func TestWithKeyDerivesStable32ByteKey(t *testing.T) {
	var a, b Config
	WithKey("correct horse battery staple")(&a)
	WithKey("correct horse battery staple")(&b)
	if len(a.RawKey) != 32 {
		t.Fatalf("WithKey RawKey len = %d, want 32", len(a.RawKey))
	}
	if !reflect.DeepEqual(a.RawKey, b.RawKey) {
		t.Fatal("WithKey gave different keys for the same passphrase")
	}

	var c Config
	WithKey("a different passphrase")(&c)
	if reflect.DeepEqual(a.RawKey, c.RawKey) {
		t.Fatal("WithKey gave the same key for different passphrases")
	}

	// WithKey must not touch any other field.
	a.RawKey, b.RawKey, c.RawKey = nil, nil, nil
	if !reflect.DeepEqual(a, Config{}) {
		t.Fatalf("WithKey changed non-key fields: %+v", a)
	}
}

// TestWithRaftSetsFields pins exactly what WithRaft writes into Config.
func TestWithRaftSetsFields(t *testing.T) {
	peers := []string{"n2:7000", "n3:7000"}
	var c Config
	WithRaft("n1", ":7000", peers)(&c)
	want := Config{Mode: ModeRaft, NodeID: "n1", Listen: ":7000", Peers: peers}
	if !reflect.DeepEqual(c, want) {
		t.Fatalf("WithRaft Config = %+v, want %+v", c, want)
	}
}

// TestWithCRDTSetsFields pins exactly what WithCRDT writes into Config.
func TestWithCRDTSetsFields(t *testing.T) {
	peers := []string{"n2:7000"}
	var c Config
	WithCRDT("n1", ":7000", peers)(&c)
	want := Config{Mode: ModeCRDT, NodeID: "n1", Listen: ":7000", Peers: peers}
	if !reflect.DeepEqual(c, want) {
		t.Fatalf("WithCRDT Config = %+v, want %+v", c, want)
	}
}

// TestWithThresholdSetsFields pins exactly what WithThreshold writes into Config.
func TestWithThresholdSetsFields(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	var c Config
	WithThreshold(2, 3, priv)(&c)
	want := Config{Mode: ModeThreshold, Threshold: 2, Parties: 3, SigningKey: priv}
	if !reflect.DeepEqual(c, want) {
		t.Fatalf("WithThreshold Config = %+v, want %+v", c, want)
	}
}

// TestWithPeersOnlySetsPeers pins that WithPeers changes Peers and nothing else.
func TestWithPeersOnlySetsPeers(t *testing.T) {
	peers := []string{"n1:7000", "n2:7000"}
	var c Config
	WithPeers(peers)(&c)
	want := Config{Peers: peers}
	if !reflect.DeepEqual(c, want) {
		t.Fatalf("WithPeers Config = %+v, want %+v", c, want)
	}
}

// TestEncryptedReflectsKey opens one keyed and one unkeyed temp database and
// checks DB.Encrypted reports true and false respectively.
func TestEncryptedReflectsKey(t *testing.T) {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatalf("rand.Read: %v", err)
	}

	keyed, err := Open(filepath.Join(t.TempDir(), "keyed.db"), WithRawKey(key))
	if err != nil {
		t.Fatalf("Open with key: %v", err)
	}
	defer keyed.Close()
	if !keyed.Encrypted() {
		t.Fatal("Encrypted() = false for a database opened with a key, want true")
	}

	plain, err := Open(filepath.Join(t.TempDir(), "plain.db"))
	if err != nil {
		t.Fatalf("Open without key: %v", err)
	}
	defer plain.Close()
	if plain.Encrypted() {
		t.Fatal("Encrypted() = true for a database opened without a key, want false")
	}

	// A WithKey passphrase also marks the database encrypted.
	pass, err := Open(filepath.Join(t.TempDir(), "pass.db"), WithKey("s3cret"))
	if err != nil {
		t.Fatalf("Open with WithKey: %v", err)
	}
	defer pass.Close()
	if !pass.Encrypted() {
		t.Fatal("Encrypted() = false for a database opened with WithKey, want true")
	}
}
