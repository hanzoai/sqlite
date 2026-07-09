package sqlite

import (
	"database/sql"
	"os"
	"path/filepath"
	"testing"
)

// seedPlaintext creates a plaintext SQLite db at path with a mixed-type table
// (incl. SQL NULL, blob, int, float, text) and returns the row count.
func seedPlaintext(t *testing.T, path string) int {
	t.Helper()
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatalf("open plaintext: %v", err)
	}
	defer db.Close()
	execSQL(t, db, `CREATE TABLE acct (id INTEGER PRIMARY KEY, name TEXT, bal REAL, blob BLOB, note TEXT)`)
	execSQL(t, db, `CREATE INDEX idx_acct_name ON acct(name)`)
	execSQL(t, db, `INSERT INTO acct (id,name,bal,blob,note) VALUES (1,'alice',12.34,x'DEADBEEF','hi')`)
	execSQL(t, db, `INSERT INTO acct (id,name,bal,blob,note) VALUES (2,'bob',0.0,NULL,NULL)`)      // NULLs preserved?
	execSQL(t, db, `INSERT INTO acct (id,name,bal,blob,note) VALUES (3,NULL,-1.5,x'00','café €')`) // NULL name, unicode
	execSQL(t, db, `PRAGMA user_version=7`)
	return 3
}

func execSQL(t *testing.T, db *sql.DB, q string, args ...any) {
	t.Helper()
	if _, err := db.Exec(q, args...); err != nil {
		t.Fatalf("exec %q: %v", q, err)
	}
}

func rowCount(t *testing.T, db *sql.DB, tbl string) int {
	t.Helper()
	var n int
	if err := db.QueryRow(`SELECT count(*) FROM ` + tbl).Scan(&n); err != nil {
		t.Fatalf("count %s: %v", tbl, err)
	}
	return n
}

func testKey() []byte {
	k := make([]byte, 32)
	for i := range k {
		k[i] = byte(i*7 + 1)
	}
	return k
}

// TestOpenEnvelopedPlaintextPassthrough runs under BOTH backends: a nil master
// key must behave exactly like sql.Open (no key, plaintext), so existing callers
// are untouched when encryption is off.
func TestOpenEnvelopedPlaintextPassthrough(t *testing.T) {
	path := filepath.Join(t.TempDir(), "plain.db")
	db, err := OpenEnveloped(path, nil, PrincipalGlobal, "test")
	if err != nil {
		t.Fatalf("OpenEnveloped nil key: %v", err)
	}
	execSQL(t, db, `CREATE TABLE t (v TEXT)`)
	execSQL(t, db, `INSERT INTO t (v) VALUES ('x')`)
	if n := rowCount(t, db, "t"); n != 1 {
		t.Fatalf("row count = %d, want 1", n)
	}
	db.Close()
	// No sidecar is created for the plaintext posture.
	if fileExists(path + dekSuffix) {
		t.Fatalf("plaintext posture must not write a .dek sidecar")
	}
	plain, err := isPlaintextSQLiteFile(path)
	if err != nil || !plain {
		t.Fatalf("nil-key file must be plaintext SQLite (plain=%v err=%v)", plain, err)
	}
}

// requireCodec skips a test on a build without the SQLCipher codec linked (pure-Go
// or cgo-without-libsqlcipher). The Dockerfile build links it and runs these under
// SQLITE_REQUIRE_CODEC=1, turning the skip into a hard gate.
func requireCodec(t *testing.T) {
	t.Helper()
	if !CodecLinked() {
		if os.Getenv("SQLITE_REQUIRE_CODEC") == "1" {
			t.Fatal("SQLITE_REQUIRE_CODEC=1 but CodecLinked()=false — build did not link libsqlcipher")
		}
		t.Skip("SQLCipher codec not linked in this build; skipping at-rest encryption assertion")
	}
}

// TestMigrateFileToEncrypted_RoundTrip proves the core zero-data-loss migration:
// a plaintext money-shaped db becomes ciphertext at rest, keeps a .plaintext.bak,
// and reopens under the derived key with every row (incl. NULLs/blobs) intact.
func TestMigrateFileToEncrypted_RoundTrip(t *testing.T) {
	requireCodec(t)
	dir := t.TempDir()
	path := filepath.Join(dir, "money.db")
	want := seedPlaintext(t, path)

	rows, changed, err := MigrateFileToEncrypted(path, testKey(), PrincipalGlobal, "money")
	if err != nil {
		t.Fatalf("migrate: %v", err)
	}
	if !changed || rows != want {
		t.Fatalf("migrate changed=%v rows=%d, want changed=true rows=%d", changed, rows, want)
	}

	// At rest: ciphertext (no plaintext header), sidecar present, plaintext.bak kept.
	if plain, _ := isPlaintextSQLiteFile(path); plain {
		t.Fatalf("migrated file still has the plaintext SQLite header — NOT encrypted")
	}
	if !fileExists(path + dekSuffix) {
		t.Fatalf("missing .dek sidecar after migration")
	}
	if !fileExists(path + plaintextBakSuffix) {
		t.Fatalf("missing .plaintext.bak backup after migration")
	}

	// Reopen enveloped → all rows + user_version preserved.
	db, err := OpenEnveloped(path, testKey(), PrincipalGlobal, "money")
	if err != nil {
		t.Fatalf("reopen enveloped: %v", err)
	}
	defer db.Close()
	if n := rowCount(t, db, "acct"); n != want {
		t.Fatalf("reopened row count = %d, want %d", n, want)
	}
	var uv int
	if err := db.QueryRow(`PRAGMA user_version`).Scan(&uv); err != nil || uv != 7 {
		t.Fatalf("user_version = %d (err %v), want 7", uv, err)
	}
	// Spot-check NULL fidelity: id=2 has NULL blob+note (name='bob'); id=3 has NULL name.
	var blob []byte
	var note sql.NullString
	if err := db.QueryRow(`SELECT blob, note FROM acct WHERE id=2`).Scan(&blob, &note); err != nil {
		t.Fatalf("select id=2: %v", err)
	}
	if blob != nil || note.Valid {
		t.Fatalf("id=2 NULLs not preserved: blob=%v note.Valid=%v", blob, note.Valid)
	}
	var name3 sql.NullString
	if err := db.QueryRow(`SELECT name FROM acct WHERE id=3`).Scan(&name3); err != nil {
		t.Fatalf("select id=3: %v", err)
	}
	if name3.Valid {
		t.Fatalf("id=3 NULL name not preserved: name=%q", name3.String)
	}
	// And the blob at id=1 must survive byte-identically.
	var b1 []byte
	if err := db.QueryRow(`SELECT blob FROM acct WHERE id=1`).Scan(&b1); err != nil {
		t.Fatalf("select id=1 blob: %v", err)
	}
	if len(b1) != 4 || b1[0] != 0xDE || b1[1] != 0xAD || b1[2] != 0xBE || b1[3] != 0xEF {
		t.Fatalf("id=1 blob corrupted: %x", b1)
	}
}

// TestMigrateFileToEncrypted_Idempotent: a second run is a no-op (sidecar present).
func TestMigrateFileToEncrypted_Idempotent(t *testing.T) {
	requireCodec(t)
	path := filepath.Join(t.TempDir(), "idem.db")
	seedPlaintext(t, path)
	if _, changed, err := MigrateFileToEncrypted(path, testKey(), PrincipalGlobal, "idem"); err != nil || !changed {
		t.Fatalf("first migrate changed=%v err=%v", changed, err)
	}
	_, changed, err := MigrateFileToEncrypted(path, testKey(), PrincipalGlobal, "idem")
	if err != nil {
		t.Fatalf("second migrate err: %v", err)
	}
	if changed {
		t.Fatalf("second migrate must be a no-op (changed=false)")
	}
}

// TestOpenEnveloped_FreshCreatesEncrypted: opening a non-existent path with a key
// creates a fresh ENCRYPTED file + sidecar (never a plaintext one).
func TestOpenEnveloped_FreshCreatesEncrypted(t *testing.T) {
	requireCodec(t)
	path := filepath.Join(t.TempDir(), "fresh.db")
	db, err := OpenEnveloped(path, testKey(), PrincipalGlobal, "fresh")
	if err != nil {
		t.Fatalf("open fresh: %v", err)
	}
	execSQL(t, db, `CREATE TABLE t (v TEXT)`)
	execSQL(t, db, `INSERT INTO t (v) VALUES ('secret')`)
	db.Close()
	if !fileExists(path + dekSuffix) {
		t.Fatalf("fresh encrypted open must write a .dek sidecar")
	}
	if plain, _ := isPlaintextSQLiteFile(path); plain {
		t.Fatalf("fresh file is plaintext — codec not applied")
	}
	// Reopen and read back.
	db2, err := OpenEnveloped(path, testKey(), PrincipalGlobal, "fresh")
	if err != nil {
		t.Fatalf("reopen fresh: %v", err)
	}
	defer db2.Close()
	if n := rowCount(t, db2, "t"); n != 1 {
		t.Fatalf("fresh reopen row count = %d, want 1", n)
	}
}

// TestOpenEnveloped_SelfHealsPlaintext: OpenEnveloped on a plaintext file with a
// key migrates it in place, then serves it encrypted.
func TestOpenEnveloped_SelfHealsPlaintext(t *testing.T) {
	requireCodec(t)
	path := filepath.Join(t.TempDir(), "heal.db")
	want := seedPlaintext(t, path)
	db, err := OpenEnveloped(path, testKey(), PrincipalGlobal, "heal")
	if err != nil {
		t.Fatalf("self-heal open: %v", err)
	}
	defer db.Close()
	if n := rowCount(t, db, "acct"); n != want {
		t.Fatalf("self-heal row count = %d, want %d", n, want)
	}
	if plain, _ := isPlaintextSQLiteFile(path); plain {
		t.Fatalf("self-heal left the file plaintext")
	}
}

// TestOpenEnveloped_RefusesCipherWithoutSidecar: an encrypted file whose sidecar
// is gone must NOT be treated as fresh/plaintext — refuse (fail closed).
func TestOpenEnveloped_RefusesCipherWithoutSidecar(t *testing.T) {
	requireCodec(t)
	path := filepath.Join(t.TempDir(), "lost.db")
	seedPlaintext(t, path)
	if _, _, err := MigrateFileToEncrypted(path, testKey(), PrincipalGlobal, "lost"); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	if err := os.Remove(path + dekSuffix); err != nil {
		t.Fatalf("rm sidecar: %v", err)
	}
	if _, err := OpenEnveloped(path, testKey(), PrincipalGlobal, "lost"); err == nil {
		t.Fatalf("expected refusal opening a ciphertext file with no sidecar")
	}
}

// TestOpenEnveloped_WrongMasterKeyFails: the wrong master key fails the GCM tag,
// never a partial/garbage open.
func TestOpenEnveloped_WrongMasterKeyFails(t *testing.T) {
	requireCodec(t)
	path := filepath.Join(t.TempDir(), "wrong.db")
	seedPlaintext(t, path)
	if _, _, err := MigrateFileToEncrypted(path, testKey(), PrincipalGlobal, "wrong"); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	other := make([]byte, 32)
	for i := range other {
		other[i] = byte(255 - i)
	}
	if _, err := OpenEnveloped(path, other, PrincipalGlobal, "wrong"); err == nil {
		t.Fatalf("expected wrong-master-key open to fail")
	}
}
