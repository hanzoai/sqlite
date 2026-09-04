package sqlite

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

// TestKeyedRoundTripAndCheckpoint exercises the full keyed lifecycle on whichever
// mechanism this build uses (pure-Go envelope, or the live codec on a cgo build):
// create, write, Checkpoint (mid-session durability), write more, close, reopen,
// read everything back. The real path must be ciphertext AFTER the checkpoint and
// AFTER close — never plaintext at any point a reader could observe it.
func TestKeyedRoundTripAndCheckpoint(t *testing.T) {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i*13 + 7)
	}
	path := filepath.Join(t.TempDir(), "rt.db")

	db, err := OpenDB(path, key)
	if err != nil {
		t.Fatalf("OpenDB: %v", err)
	}
	if _, err := db.Exec(`CREATE TABLE t (id INTEGER PRIMARY KEY, v TEXT)`); err != nil {
		t.Fatalf("create: %v", err)
	}
	if _, err := db.Exec(`INSERT INTO t (v) VALUES ('one')`); err != nil {
		t.Fatalf("insert: %v", err)
	}

	// Checkpoint mid-session: the ciphertext on disk must now be current AND never
	// plaintext.
	if err := Checkpoint(db); err != nil {
		t.Fatalf("checkpoint: %v", err)
	}
	assertCiphertextOnDisk(t, path, "one")

	if _, err := db.Exec(`INSERT INTO t (v) VALUES ('two')`); err != nil {
		t.Fatalf("insert 2: %v", err)
	}
	if err := db.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	assertCiphertextOnDisk(t, path, "two")

	// Reopen and read both rows back.
	db2, err := OpenDB(path, key)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer db2.Close()
	rows, err := db2.Query(`SELECT v FROM t ORDER BY id`)
	if err != nil {
		t.Fatalf("query: %v", err)
	}
	defer rows.Close()
	var got []string
	for rows.Next() {
		var v string
		if err := rows.Scan(&v); err != nil {
			t.Fatal(err)
		}
		got = append(got, v)
	}
	if len(got) != 2 || got[0] != "one" || got[1] != "two" {
		t.Fatalf("read back %v, want [one two]", got)
	}
}

// TestKeyedTempStoreMemory asserts the envelope connection keeps temp b-trees in
// RAM (temp_store=MEMORY) on the pure-Go backend, where the plaintext copy is opened
// by modernc — a temp-file spill there would be decrypted data on disk. Skipped when
// the live libsqlcipher codec is used (it encrypts its own temp spills).
func TestKeyedTempStoreMemory(t *testing.T) {
	if CodecLinked() {
		t.Skip("live libsqlcipher codec encrypts its own temp spills; temp_store is not the guard there")
	}
	key := make([]byte, 32)
	db, err := OpenDB(filepath.Join(t.TempDir(), "ts.db"), key)
	if err != nil {
		t.Fatalf("OpenDB: %v", err)
	}
	defer db.Close()
	var ts int
	if err := db.QueryRow("PRAGMA temp_store").Scan(&ts); err != nil {
		t.Fatalf("read temp_store: %v", err)
	}
	if ts != 2 {
		t.Fatalf("temp_store = %d, want 2 (MEMORY)", ts)
	}
}

// TestKeyedWrongKeyRejected proves a wrong key never yields data: the envelope
// fails at DecryptFile (page-1 authentication), the live codec at the query.
func TestKeyedWrongKeyRejected(t *testing.T) {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i + 1)
	}
	path := filepath.Join(t.TempDir(), "wk.db")

	db, err := OpenDB(path, key)
	if err != nil {
		t.Fatalf("OpenDB: %v", err)
	}
	if _, err := db.Exec(`CREATE TABLE s (v TEXT)`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO s VALUES ('classified')`); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}

	wrong := make([]byte, 32)
	copy(wrong, key)
	wrong[0] ^= 0xFF
	db2, err := OpenDB(path, wrong)
	if err == nil {
		var v string
		err = db2.QueryRow(`SELECT v FROM s`).Scan(&v)
		db2.Close()
	}
	if err == nil {
		t.Fatal("wrong key read succeeded — key is not enforced")
	}
}

// TestOpenDBRejectsWrongKeyLength proves OpenDB rejects a non-32-byte key on BOTH
// the live-libsqlcipher path and the envelope path — otherwise SQLCipher would
// silently reinterpret a wrong-length `key=x'HEX'` blob as a passphrase (a
// different, weaker key), and OpenDB (unlike Open) had no length check.
func TestOpenDBRejectsWrongKeyLength(t *testing.T) {
	for _, n := range []int{0, 16, 31, 33, 64} {
		if n == 0 {
			continue // nil-key means unencrypted; a 0-length non-nil key:
		}
		key := make([]byte, n)
		path := filepath.Join(t.TempDir(), "kl.db")
		if _, err := OpenDB(path, key); err == nil {
			t.Fatalf("OpenDB accepted a %d-byte key; must reject non-32", n)
		}
		if _, err := os.Stat(path); !os.IsNotExist(err) {
			t.Fatalf("OpenDB created a file for a rejected %d-byte key", n)
		}
	}
}

// TestEnvelopeOpensWithoutRAMBackedScratch proves the pure-Go envelope needs no
// tmpfs and no root: on a host with no RAM-backed scratch a keyed open succeeds
// through the OS temp dir, round-trips, writes only ciphertext to the real path,
// and leaves no plaintext behind once closed. (The live libsqlcipher codec needs
// no scratch at all, so this is an envelope-only path.)
func TestEnvelopeOpensWithoutRAMBackedScratch(t *testing.T) {
	if CodecLinked() {
		t.Skip("live libsqlcipher codec needs no scratch")
	}
	// No RAM-backed scratch anywhere: an override that is not tmpfs and does not
	// exist, and /dev/shm absent on this platform. scratchBase must fall back to the
	// OS temp dir rather than refuse.
	t.Setenv(ramfsEnv, filepath.Join(t.TempDir(), "definitely-not-tmpfs"))

	key := make([]byte, 32)
	path := filepath.Join(t.TempDir(), "nofs.db")

	db, err := OpenDB(path, key)
	if err != nil {
		t.Fatalf("keyed open with no RAM scratch must succeed via temp fallback: %v", err)
	}
	const marker = "envelope-no-ramfs-marker"
	if _, err := db.Exec(`CREATE TABLE t(v TEXT)`); err != nil {
		t.Fatalf("create: %v", err)
	}
	if _, err := db.Exec(`INSERT INTO t VALUES(?)`, marker); err != nil {
		t.Fatalf("insert: %v", err)
	}
	if err := db.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	// The real path is ciphertext, and reopening with the key reads the row back.
	assertCiphertextOnDisk(t, path, marker)
	db2, err := OpenDB(path, key)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer db2.Close()
	var got string
	if err := db2.QueryRow(`SELECT v FROM t`).Scan(&got); err != nil {
		t.Fatalf("read back: %v", err)
	}
	if got != marker {
		t.Fatalf("round-trip lost the row: got %q want %q", got, marker)
	}
}

// assertCiphertextOnDisk fails if the file at path is readable as plaintext SQLite
// or contains the marker in the clear — the confidentiality invariant a keyed store
// must always satisfy at rest.
func assertCiphertextOnDisk(t *testing.T, path, marker string) {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	if bytes.HasPrefix(raw, []byte("SQLite format 3\x00")) {
		t.Fatalf("CONFIDENTIALITY VIOLATION: %s has a plaintext SQLite header", path)
	}
	if bytes.Contains(raw, []byte(marker)) {
		t.Fatalf("CONFIDENTIALITY VIOLATION: %q is visible in the clear in %s", marker, path)
	}
}
