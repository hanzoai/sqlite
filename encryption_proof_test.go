package sqlite

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

// TestEncryptionProof is the anti-silent-plaintext gate.
//
// On the !cgo (pure-Go) backend, encryption is unavailable: Open with a key MUST
// return ErrEncryptionUnavailable and never write a file.
//
// On the cgo backend, EncryptionAvailable() reports true — but that is only a
// backend-capability flag. A cgo build that forgot to link libsqlcipher (e.g. a
// regression back to the inert `-tags sqlcipher`) links plain sqlite and silently
// writes PLAINTEXT. This test forces the issue: under cgo it writes a known
// marker under a key and asserts the on-disk bytes are real ciphertext (no
// "SQLite format 3" header, marker absent) AND that the data survives a reopen
// with the same key. A mis-linked production build therefore FAILS CI instead of
// shipping a plaintext database.
func TestEncryptionProof(t *testing.T) {
	const marker = "anti-plaintext-canary-7f3a"
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i*7 + 1)
	}

	dir := t.TempDir()
	dbPath := filepath.Join(dir, "proof.db")

	if !EncryptionAvailable() {
		// Pure-Go backend: a keyed Open must be refused, with no file created.
		if _, err := Open(dbPath, WithRawKey(key)); err != ErrEncryptionUnavailable {
			t.Fatalf("!cgo Open with key: got err=%v, want ErrEncryptionUnavailable", err)
		}
		if _, statErr := os.Stat(dbPath); !os.IsNotExist(statErr) {
			t.Fatalf("!cgo backend created a file for a refused encrypted open: %v", statErr)
		}
		return
	}

	// cgo backend: prove the bytes on disk are ciphertext.
	db, err := Open(dbPath, WithRawKey(key))
	if err != nil {
		t.Fatalf("cgo Open with key: %v", err)
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
		t.Fatal("ENCRYPTION FAILURE: encrypted db has a plaintext SQLite header — libsqlcipher is not linked (build with -tags libsqlite3 + libsqlcipher, CGO_CFLAGS=-DSQLITE_HAS_CODEC -DSQLITE_USE_URI=1)")
	}
	if bytes.Contains(raw, []byte(marker)) {
		t.Fatal("ENCRYPTION FAILURE: plaintext marker found in encrypted db file — data is NOT encrypted at rest")
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

	// A different key must be rejected on reopen.
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
