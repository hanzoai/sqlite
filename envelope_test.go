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
	skipIfNoEnvelopeScratch(t)
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

// TestKeyedWrongKeyRejected proves a wrong key never yields data: the envelope
// fails at DecryptFile (page-1 authentication), the live codec at the query.
func TestKeyedWrongKeyRejected(t *testing.T) {
	skipIfNoEnvelopeScratch(t)
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

// TestEnvelopeFailsClosedWithoutRAMFS proves the confidentiality-critical property:
// when the pure-Go codec envelope cannot get RAM-backed scratch, a keyed open FAILS
// CLOSED and writes NO file — it never decrypts to persistent storage. (The live
// libsqlcipher codec needs no scratch, so this is an envelope-only property.)
func TestEnvelopeFailsClosedWithoutRAMFS(t *testing.T) {
	if CodecLinked() {
		t.Skip("live libsqlcipher codec needs no RAM-backed scratch")
	}
	// Point the resolver at a path that is not RAM-backed (does not exist ⇒ statfs
	// fails ⇒ isRAMBacked false), so ramfsBase must refuse.
	t.Setenv(ramfsEnv, filepath.Join(t.TempDir(), "definitely-not-tmpfs"))

	key := make([]byte, 32)
	path := filepath.Join(t.TempDir(), "fc.db")
	if _, err := OpenDB(path, key); err == nil {
		t.Fatal("keyed open succeeded with no RAM-backed scratch — it must fail closed")
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("a fail-closed keyed open created a file at %s", path)
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
