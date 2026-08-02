package sqlite

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

// TestEncryptionProof is the anti-silent-plaintext gate: a keyed store is ALWAYS
// ciphertext at rest, on every backend.
//
// EncryptionAvailable() is always true, so there is no refuse branch: whether the
// key is applied by the live libsqlcipher codec or by the pure-Go codec envelope,
// Open(key) must write ciphertext (no "SQLite format 3" header, marker absent), a
// keyed reopen must read the row back, and a wrong key must be rejected. A build
// that would ship plaintext can never pass this.
func TestEncryptionProof(t *testing.T) {
	skipIfNoEnvelopeScratch(t)

	const marker = "anti-plaintext-canary-7f3a"
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i*7 + 1)
	}

	dir := t.TempDir()
	dbPath := filepath.Join(dir, "proof.db")

	db, err := Open(dbPath, WithRawKey(key))
	if err != nil {
		t.Fatalf("Open with key: %v", err)
	}
	if _, err := db.Exec(`CREATE TABLE c (v TEXT)`); err != nil {
		t.Fatalf("create: %v", err)
	}
	if _, err := db.Exec(`INSERT INTO c (v) VALUES (?)`, marker); err != nil {
		t.Fatalf("insert: %v", err)
	}
	if err := db.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	raw, err := os.ReadFile(dbPath)
	if err != nil {
		t.Fatalf("read db file: %v", err)
	}
	if bytes.HasPrefix(raw, []byte("SQLite format 3\x00")) {
		t.Fatal("ENCRYPTION FAILURE: keyed db has a plaintext SQLite header — the key was not applied")
	}
	if bytes.Contains(raw, []byte(marker)) {
		t.Fatal("ENCRYPTION FAILURE: plaintext marker found in keyed db file — data is NOT encrypted at rest")
	}

	// Reopen-with-key must read the row back (proves keyed reopen works).
	db2, err := Open(dbPath, WithRawKey(key))
	if err != nil {
		t.Fatalf("reopen with key: %v", err)
	}
	defer db2.Close()
	var got string
	if err := db2.QueryRow(`SELECT v FROM c`).Scan(&got); err != nil {
		t.Fatalf("reopen read: %v", err)
	}
	if got != marker {
		t.Fatalf("reopen read = %q, want %q", got, marker)
	}

	// A different key must be rejected on reopen — the envelope fails at DecryptFile
	// (page-1 authentication), the live codec at the first query.
	wrong := make([]byte, 32)
	copy(wrong, key)
	wrong[0] ^= 0xFF
	db3, err := Open(dbPath, WithRawKey(wrong))
	if err == nil {
		var x string
		err = db3.QueryRow(`SELECT v FROM c`).Scan(&x)
		db3.Close()
	}
	if err == nil {
		t.Fatal("ENCRYPTION FAILURE: wrong key read succeeded — key is not enforced")
	}
}

// skipIfNoEnvelopeScratch skips a test that would exercise the pure-Go codec
// envelope on a host with no RAM-backed scratch dir (the envelope fails closed
// there rather than decrypt to disk). When the live libsqlcipher codec is linked
// (CodecLinked), the envelope is not used and no scratch is needed.
func skipIfNoEnvelopeScratch(t *testing.T) {
	t.Helper()
	if CodecLinked() {
		return
	}
	if _, err := ramfsBase(); err != nil {
		t.Skipf("pure-Go codec envelope needs RAM-backed scratch (tmpfs): %v", err)
	}
}

// TestEnvelopeRotation proves the envelope contract that makes master-key
// rotation non-destructive (finding B3). It is pure-Go and runs under BOTH build
// tags. A random DEK is wrapped under a KEK derived from masterA, then rewrapped
// under a KEK derived from masterB; the SAME DEK must come back out — i.e. the
// page key (and therefore the encrypted file) is untouched by rotation.
