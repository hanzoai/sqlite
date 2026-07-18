package sqlite

import (
	"bytes"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"

	"github.com/hanzoai/sqlcipher"
)

// cKey is the raw 256-bit key that testdata/c-sqlcipher-4.5.6.db was written under
// by the real C SQLCipher library (copied from github.com/hanzoai/sqlcipher's
// testdata, where the byte-for-byte fixture originates).
var cKey = mustHexKey("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")

func mustHexKey(s string) []byte { b, _ := hex.DecodeString(s); return b }

// TestOpensCWrittenSQLCipherDB proves byte-compatibility one way: a database
// written by the C SQLCipher library opens and reads through this driver. On a
// pure-Go build that is the codec VFS; on a linked cgo build it is libsqlcipher.
func TestOpensCWrittenSQLCipherDB(t *testing.T) {
	if !CodecLinked() {
		t.Skip("cgo build without libsqlcipher; byte-compat proven on the pure-Go build")
	}
	// Work on a copy: opening may convert it to WAL.
	src, err := os.ReadFile("testdata/c-sqlcipher-4.5.6.db")
	if err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(t.TempDir(), "c.db")
	if err := os.WriteFile(p, src, 0o600); err != nil {
		t.Fatal(err)
	}

	db, err := Open(p, WithRawKey(cKey))
	if err != nil {
		t.Fatalf("open C-written db: %v", err)
	}
	defer db.Close()
	var n int
	if err := db.QueryRow(`SELECT count(*) FROM sqlite_master`).Scan(&n); err != nil {
		t.Fatalf("read C-written schema: %v", err)
	}
	if n == 0 {
		t.Fatal("C-written db has an empty schema — decryption likely wrong")
	}
	t.Logf("opened C-written SQLCipher db, %d schema objects", n)

	// Wrong key must be rejected, not silently return garbage.
	wrong := append([]byte(nil), cKey...)
	wrong[0] ^= 0xFF
	if bad, err := Open(p+"-nope", WithRawKey(wrong)); err == nil {
		bad.Close()
	}
	db2, err := Open(p, WithRawKey(wrong))
	if err == nil {
		err = db2.QueryRow(`SELECT count(*) FROM sqlite_master`).Scan(&n)
		db2.Close()
	}
	if err == nil {
		t.Fatal("wrong key opened the C-written db — key not enforced")
	}
}

// TestPureGoWALRoundTripAndByteCompat exercises the full encrypted lifecycle on a
// newly-created database: WAL writes, read-back before and after checkpoint,
// reopen persistence, no plaintext on disk, and byte-compatibility the OTHER way —
// a database this driver wrote decrypts with the standalone hanzoai/sqlcipher
// codec (which is itself gated byte-for-byte against C SQLCipher).
func TestPureGoWALRoundTripAndByteCompat(t *testing.T) {
	if !CodecLinked() {
		t.Skip("cgo build without libsqlcipher; run on the pure-Go build")
	}
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i*11 + 3)
	}
	dir := t.TempDir()
	p := filepath.Join(dir, "store.db")

	db, err := Open(p, WithRawKey(key))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if _, err := db.Exec(`CREATE TABLE t(id INTEGER PRIMARY KEY, v BLOB)`); err != nil {
		t.Fatalf("create: %v", err)
	}
	blob := bytes.Repeat([]byte{0x5A}, 400)
	tx, _ := db.Begin()
	st, _ := tx.Prepare(`INSERT INTO t(v) VALUES(?)`)
	for i := 0; i < 1500; i++ { // enough rows to spill many WAL frames + new pages
		if _, err := st.Exec(blob); err != nil {
			t.Fatalf("insert %d: %v", i, err)
		}
	}
	st.Close()
	if err := tx.Commit(); err != nil {
		t.Fatalf("commit: %v", err)
	}

	// Read back BEFORE checkpoint: served through the WAL via the codec.
	var n int
	if err := db.QueryRow(`SELECT count(*) FROM t`).Scan(&n); err != nil || n != 1500 {
		t.Fatalf("read from WAL: n=%d err=%v (want 1500)", n, err)
	}
	var got []byte
	if err := db.QueryRow(`SELECT v FROM t WHERE id=750`).Scan(&got); err != nil || !bytes.Equal(got, blob) {
		t.Fatalf("WAL row 750 mismatch: err=%v", err)
	}
	if _, err := db.Exec(`PRAGMA wal_checkpoint(TRUNCATE)`); err != nil {
		t.Fatalf("checkpoint: %v", err)
	}
	if err := db.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	// Reopen: data persisted, decrypts from the main file.
	db2, err := Open(p, WithRawKey(key))
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	if err := db2.QueryRow(`SELECT count(*) FROM t`).Scan(&n); err != nil || n != 1500 {
		db2.Close()
		t.Fatalf("after reopen: n=%d err=%v (want 1500)", n, err)
	}
	// Write MORE after reopen (WAL again on an existing db).
	if _, err := db2.Exec(`INSERT INTO t(v) VALUES(?)`, blob); err != nil {
		db2.Close()
		t.Fatalf("post-reopen insert: %v", err)
	}
	db2.Exec(`PRAGMA wal_checkpoint(TRUNCATE)`)
	db2.Close()

	// No plaintext on disk.
	raw, _ := os.ReadFile(p)
	if bytes.HasPrefix(raw, []byte("SQLite format 3\x00")) {
		t.Fatal("main db has a plaintext SQLite header — not encrypted")
	}
	if bytes.Contains(raw, blob) {
		t.Fatal("plaintext row blob found on disk — not encrypted")
	}

	// Byte-compat (the other direction): the standalone codec decrypts what this
	// driver wrote, yielding a valid plaintext SQLite database.
	os.Remove(p + "-wal")
	in, err := os.Open(p)
	if err != nil {
		t.Fatal(err)
	}
	defer in.Close()
	var plain bytes.Buffer
	if err := sqlcipher.DecryptFile(&plain, in, sqlcipher.RawKey(key), sqlcipher.Params{}); err != nil {
		t.Fatalf("standalone codec could not decrypt driver-written db: %v", err)
	}
	if !bytes.HasPrefix(plain.Bytes(), []byte("SQLite format 3\x00")) {
		t.Fatal("decrypted output is not a valid SQLite database — format mismatch with C SQLCipher")
	}
	t.Logf("OK: %d encrypted bytes on disk, WAL round-tripped, byte-compatible both ways", len(raw))
}
