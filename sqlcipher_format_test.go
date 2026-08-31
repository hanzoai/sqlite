package sqlite

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/hanzoai/sqlcipher"
)

// A keyed store is SQLCipher 4, and OUR pure-Go reader is what proves it.
//
// TestEncryptionProof beside this asserts the file is not plaintext, which any
// cipher satisfies — a backend that invented its own format would pass it and
// leave a database no other Hanzo build could open. This asserts the FORMAT:
// `github.com/hanzoai/sqlcipher` decrypts the file with the same key and finds a
// real SQLite database with the row in it.
//
// It runs under BOTH build tags on purpose, and that is the interoperability the
// estate depends on: the C libsqlcipher writes what our pure-Go codec reads, so a
// store written by a CGO_ENABLED=0 build opens in the image, and one written by
// the image opens in a pure-Go tool. Under cgo it additionally proves the C
// library really is SQLCipher rather than a plain SQLite that ignored the key.
func TestKeyedFileIsOurSQLCipher(t *testing.T) {
	skipIfNoEnvelopeScratch(t)

	const marker = "sqlcipher-format-canary-1d4e"
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i*11 + 3)
	}

	path := filepath.Join(t.TempDir(), "format.db")
	db, err := Open(path, WithRawKey(key))
	if err != nil {
		t.Fatalf("open with key: %v", err)
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

	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read: %v", err)
	}

	var plain bytes.Buffer
	if err := sqlcipher.DecryptFile(&plain, bytes.NewReader(raw), sqlcipher.RawKey(key), sqlcipher.Params{}); err != nil {
		t.Fatalf("hanzoai/sqlcipher could not decrypt the keyed store, so it is not SQLCipher 4 under this key: %v", err)
	}
	if !bytes.HasPrefix(plain.Bytes(), []byte("SQLite format 3\x00")) {
		t.Fatal("decrypted bytes are not a SQLite database: the file is ciphertext of something else")
	}
	if !bytes.Contains(plain.Bytes(), []byte(marker)) {
		t.Fatal("the row is not in the decrypted database: the key opened it and the content is not ours")
	}
}
