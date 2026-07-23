//go:build cgo && !sqlite_purego

package sqlite

import (
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
)

// TestFailClosedOnMislinkedCodec simulates the confidentiality bug and proves the
// fix. A cgo build whose linked SQLite is NOT SQLCipher (plain libsqlite3, or
// libsqlcipher absent) silently no-ops PRAGMA key and writes PLAINTEXT, while the
// old compile-time EncryptionAvailable() reported "available". This forces the
// codec probe to report that plaintext-fallback state and asserts every keyed
// entry point FAILS CLOSED — ErrEncryptionUnavailable, no file — instead of
// handing the key to a plain engine that would write cleartext.
//
// It exercises BOTH Open and OpenDB: OpenDB is the entry cek/openKeyed uses, and
// it previously bypassed Open()'s gate entirely — the exact path that let cek
// believe it had encrypted while the pages were plaintext.
func TestFailClosedOnMislinkedCodec(t *testing.T) {
	atomic.StoreInt32(&probeOverride, 2) // 2 = force "codec does not encrypt"
	defer atomic.StoreInt32(&probeOverride, 0)

	if EncryptionAvailable() {
		t.Fatal("forced probe not honored: EncryptionAvailable() must be false")
	}
	if CodecLinked() {
		t.Fatal("forced probe not honored: CodecLinked() must be false")
	}

	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i + 9)
	}
	dir := t.TempDir()

	// Open(path, key) must fail closed and create no file.
	p1 := filepath.Join(dir, "open.db")
	if _, err := Open(p1, WithRawKey(key)); err != ErrEncryptionUnavailable {
		t.Fatalf("Open with key: got err=%v, want ErrEncryptionUnavailable", err)
	}
	if _, err := os.Stat(p1); !os.IsNotExist(err) {
		t.Fatalf("Open created a file on a fail-closed keyed open: %v", err)
	}

	// OpenDB(path, key) — the cek path that bypassed Open's gate — must ALSO fail
	// closed and create no file. This is the regression gate for the bypass.
	p2 := filepath.Join(dir, "opendb.db")
	if _, err := OpenDB(p2, key); err != ErrEncryptionUnavailable {
		t.Fatalf("OpenDB with key: got err=%v, want ErrEncryptionUnavailable", err)
	}
	if _, err := os.Stat(p2); !os.IsNotExist(err) {
		t.Fatalf("OpenDB created a file on a fail-closed keyed open: %v", err)
	}
}

// TestProbeTruePositive asserts that, on a build where the real probe reports
// encryption available (libsqlcipher linked), a keyed OpenDB actually writes
// ciphertext — the true-positive companion to the fail-closed simulation. It
// skips when this build genuinely cannot encrypt (the refuse path is covered by
// TestEncryptionProof).
func TestProbeTruePositive(t *testing.T) {
	if !EncryptionAvailable() {
		t.Skip("codec not linked in this build; true-positive path not exercisable")
	}
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i*11 + 3)
	}
	path := filepath.Join(t.TempDir(), "tp.db")
	db, err := OpenDB(path, key)
	if err != nil {
		t.Fatalf("OpenDB with key on an encrypting build: %v", err)
	}
	const marker = "true-positive-marker-2d7e"
	if _, err := db.Exec(`CREATE TABLE t (v TEXT)`); err != nil {
		t.Fatalf("create: %v", err)
	}
	if _, err := db.Exec(`INSERT INTO t VALUES (?)`, marker); err != nil {
		t.Fatalf("insert: %v", err)
	}
	if err := db.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if !encryptsAtRest(raw, []byte(marker)) {
		t.Fatal("keyed OpenDB wrote plaintext on a build the probe reported as encrypting")
	}
}
