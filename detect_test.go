package sqlite

import "testing"

// TestEncryptsAtRest covers the pure decision predicate behind the codec probe,
// portably (no C codec needed): plaintext is anything a SQLCipher file is not.
func TestEncryptsAtRest(t *testing.T) {
	marker := []byte("SENTINEL-9f3c")

	// A plaintext SQLite database (magic header) is NOT encrypted, even if the
	// marker happens not to appear verbatim.
	plainHeader := append([]byte("SQLite format 3\x00"), []byte("\x10\x00\x01...")...)
	if encryptsAtRest(plainHeader, marker) {
		t.Fatal("plaintext SQLite header accepted as encrypted")
	}

	// No magic header, but the sentinel is visible in the clear ⇒ not encrypted.
	if encryptsAtRest([]byte("\x9anot-a-header... SENTINEL-9f3c ...tail"), marker) {
		t.Fatal("visible sentinel accepted as encrypted")
	}

	// SQLCipher-shaped bytes: random salt where the magic would be, no sentinel in
	// the clear ⇒ genuinely encrypted.
	ct := []byte{0x9a, 0x3f, 0x00, 0x01, 0xde, 0xad, 0xbe, 0xef, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88}
	if !encryptsAtRest(ct, marker) {
		t.Fatal("ciphertext (no header, no sentinel) rejected as plaintext")
	}
}
