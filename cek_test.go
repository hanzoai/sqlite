package sqlite

import (
	"bytes"
	"crypto/rand"
	"os"
	"path/filepath"
	"testing"
)

// sqlcipherAvailable returns true if the underlying SQLite has sqlcipher
// linked. Without it, PRAGMA key is a no-op and encryption tests are
// meaningless.
func sqlcipherAvailable(t *testing.T) bool {
	t.Helper()
	dir := t.TempDir()
	mk := masterKey(t)

	// Write with a key.
	dbPath := filepath.Join(dir, "probe.db")
	db, err := Open(dbPath, WithRawKey(mk))
	if err != nil {
		return false
	}
	db.Exec("CREATE TABLE p (x TEXT)")
	db.Exec("INSERT INTO p (x) VALUES ('probe')")
	db.Close()

	// Read raw bytes -- if "SQLite format" header is present, encryption is off.
	raw, _ := os.ReadFile(dbPath)
	return !bytes.Contains(raw, []byte("SQLite format"))
}

func skipWithoutSQLCipher(t *testing.T) {
	t.Helper()
	if !sqlcipherAvailable(t) {
		t.Skip("sqlcipher not linked (build with -tags sqlcipher)")
	}
}

func masterKey(t *testing.T) []byte {
	t.Helper()
	k := make([]byte, 32)
	if _, err := rand.Read(k); err != nil {
		t.Fatal(err)
	}
	return k
}

func TestDeriveKey(t *testing.T) {
	mk := masterKey(t)
	k1, err := DeriveKey(mk, PrincipalOrg, "acme")
	if err != nil {
		t.Fatal(err)
	}
	k2, err := DeriveKey(mk, PrincipalOrg, "acme")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(k1, k2) {
		t.Fatal("same master + same principal must produce same CEK")
	}
	if len(k1) != 32 {
		t.Fatalf("CEK length: got %d, want 32", len(k1))
	}
}

func TestDeriveKeyDifferentPrincipals(t *testing.T) {
	mk := masterKey(t)
	k1, err := DeriveKey(mk, PrincipalOrg, "alpha")
	if err != nil {
		t.Fatal(err)
	}
	k2, err := DeriveKey(mk, PrincipalOrg, "beta")
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(k1, k2) {
		t.Fatal("different principals must produce different CEKs")
	}
}

func TestDeriveKeyDifferentTypes(t *testing.T) {
	mk := masterKey(t)
	k1, err := DeriveKey(mk, PrincipalOrg, "foo")
	if err != nil {
		t.Fatal(err)
	}
	k2, err := DeriveKey(mk, PrincipalUser, "foo")
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(k1, k2) {
		t.Fatal("org:foo and user:foo must produce different CEKs")
	}
}

func TestDeriveKeyBadMasterKey(t *testing.T) {
	short := make([]byte, 16)
	_, err := DeriveKey(short, PrincipalOrg, "acme")
	if err == nil {
		t.Fatal("expected error for 16-byte master key")
	}

	long := make([]byte, 64)
	_, err = DeriveKey(long, PrincipalOrg, "acme")
	if err == nil {
		t.Fatal("expected error for 64-byte master key")
	}

	_, err = DeriveKey(nil, PrincipalOrg, "acme")
	if err == nil {
		t.Fatal("expected error for nil master key")
	}
}

func TestDeriveKeyEmptyPrincipal(t *testing.T) {
	mk := masterKey(t)
	_, err := DeriveKey(mk, PrincipalOrg, "")
	if err == nil {
		t.Fatal("expected error for empty principal ID")
	}
}

func TestWithPrincipalKeyRoundTrip(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "roundtrip.db")
	mk := masterKey(t)

	// Open, write, close.
	db, err := Open(dbPath, WithPrincipalKey(mk, PrincipalOrg, "acme"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec("CREATE TABLE kv (k TEXT PRIMARY KEY, v TEXT)"); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec("INSERT INTO kv (k, v) VALUES ('hello', 'world')"); err != nil {
		t.Fatal(err)
	}
	db.Close()

	// Reopen with the same principal key, read back.
	db2, err := Open(dbPath, WithPrincipalKey(mk, PrincipalOrg, "acme"))
	if err != nil {
		t.Fatal(err)
	}
	defer db2.Close()

	var v string
	err = db2.QueryRow("SELECT v FROM kv WHERE k = 'hello'").Scan(&v)
	if err != nil {
		t.Fatal(err)
	}
	if v != "world" {
		t.Fatalf("got %q, want %q", v, "world")
	}
}

func TestWithPrincipalKeyWrongKey(t *testing.T) {
	skipWithoutSQLCipher(t)

	dir := t.TempDir()
	dbPath := filepath.Join(dir, "wrongkey.db")
	mk := masterKey(t)

	// Open with org "alpha", write data.
	db, err := Open(dbPath, WithPrincipalKey(mk, PrincipalOrg, "alpha"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec("CREATE TABLE secrets (s TEXT)"); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec("INSERT INTO secrets (s) VALUES ('classified')"); err != nil {
		t.Fatal(err)
	}
	db.Close()

	// Reopen with org "beta" (different CEK). Should fail.
	db2, err := Open(dbPath, WithPrincipalKey(mk, PrincipalOrg, "beta"))
	if err != nil {
		// Open itself can fail (ping fails) -- this is the expected path.
		return
	}

	// If Open succeeded, queries should fail.
	var s string
	err = db2.QueryRow("SELECT s FROM secrets").Scan(&s)
	db2.Close()
	if err == nil {
		t.Fatal("reading with wrong principal key should fail")
	}
}

func TestWithPrincipalKeyDerivationError(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "bad.db")

	// Bad master key length should surface on Open().
	_, err := Open(dbPath, WithPrincipalKey([]byte("short"), PrincipalOrg, "acme"))
	if err == nil {
		t.Fatal("expected error from bad master key, got nil")
	}
}

func TestWithPrincipalKeyFileIsEncrypted(t *testing.T) {
	skipWithoutSQLCipher(t)

	dir := t.TempDir()
	dbPath := filepath.Join(dir, "encrypted.db")
	mk := masterKey(t)

	db, err := Open(dbPath, WithPrincipalKey(mk, PrincipalOrg, "acme"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec("CREATE TABLE test (x TEXT)"); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec("INSERT INTO test (x) VALUES ('secret-data')"); err != nil {
		t.Fatal(err)
	}
	db.Close()

	// Read raw file bytes -- should NOT contain plaintext.
	raw, err := os.ReadFile(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(raw, []byte("secret-data")) {
		t.Fatal("plaintext found in encrypted database file")
	}
	if bytes.Contains(raw, []byte("SQLite format")) {
		t.Fatal("unencrypted SQLite header found in encrypted database file")
	}
}
