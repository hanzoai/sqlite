package sqlite

import "bytes"

// sqliteMagic is the 16-byte header of an UNENCRYPTED SQLite database.
//
// A SQLCipher 4 database has NO plaintext header: page 1 on disk is
// [ salt(16) | ciphertext | IV(16) | HMAC-SHA512(64) ], so its first bytes are
// the random per-database KDF salt, never this magic (see the SQLCipher 4 page
// format in github.com/hanzoai/sqlcipher). The presence of this magic in a file
// that was opened under a key is therefore proof the codec did NOT encrypt — the
// key was silently ignored and the pages were written in the clear.
var sqliteMagic = []byte("SQLite format 3\x00")

// encryptsAtRest reports whether raw — the on-disk bytes of a database that was
// written under an encryption key — is genuinely ciphertext. It is the pure
// decision predicate behind the codec probe (EncryptionAvailable): the bytes must
// NOT begin with the plaintext SQLite magic AND must NOT contain the sentinel
// marker in the clear. Either condition means the linked engine no-op'd the key
// and wrote plaintext, so the build cannot be trusted to encrypt at rest.
func encryptsAtRest(raw, marker []byte) bool {
	if bytes.HasPrefix(raw, sqliteMagic) {
		return false // plaintext SQLite header ⇒ codec not encrypting
	}
	if bytes.Contains(raw, marker) {
		return false // sentinel visible in the clear ⇒ not encrypted
	}
	return true
}
