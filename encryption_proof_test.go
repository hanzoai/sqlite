package sqlite

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

// TestEncryptionProof is the anti-silent-plaintext gate: a keyed store is ALWAYS
// ciphertext at rest, on every backend.
//
// EncryptionAvailable() is always true, so there is no refuse branch: whether the
// key is applied by the live libsqlcipher codec or by the pure-Go codec envelope,
// Open(key) must write ciphertext (no "SQLite format 3" header, marker absent), a
// keyed reopen must read the row back, and a wrong key must be rejected. A build
// that would ship plaintext can never pass this.
func TestEncryptionProof(t *testing.T) {
	skipIfNoEnvelopeScratch(t)

	const marker = "anti-plaintext-canary-7f3a"
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i*7 + 1)
	}

	dir := t.TempDir()
	dbPath := filepath.Join(dir, "proof.db")

	db, err := Open(dbPath, WithRawKey(key))
	if err != nil {
		t.Fatalf("Open with key: %v", err)
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
		t.Fatal("ENCRYPTION FAILURE: keyed db has a plaintext SQLite header — the key was not applied")
	}
	if bytes.Contains(raw, []byte(marker)) {
		t.Fatal("ENCRYPTION FAILURE: plaintext marker found in keyed db file — data is NOT encrypted at rest")
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

	// A different key must be rejected on reopen — the envelope fails at DecryptFile
	// (page-1 authentication), the live codec at the first query.
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

// skipIfNoEnvelopeScratch skips a test that would exercise the pure-Go codec
// envelope on a host with no RAM-backed scratch dir (the envelope fails closed
// there rather than decrypt to disk). When the live libsqlcipher codec is linked
// (CodecLinked), the envelope is not used and no scratch is needed.
func skipIfNoEnvelopeScratch(t *testing.T) {
	t.Helper()
	if CodecLinked() {
		return
	}
	if _, err := ramfsBase(); err != nil {
		t.Skipf("pure-Go codec envelope needs RAM-backed scratch (tmpfs): %v", err)
	}
}

// TestEnvelopeRotation proves the envelope contract that makes master-key
// rotation non-destructive (finding B3). It is pure-Go and runs under BOTH build
// tags. A random DEK is wrapped under a KEK derived from masterA, then rewrapped
// under a KEK derived from masterB; the SAME DEK must come back out — i.e. the
// page key (and therefore the encrypted file) is untouched by rotation.
func TestEnvelopeRotation(t *testing.T) {
	masterA := make([]byte, 32)
	masterB := make([]byte, 32)
	for i := range masterA {
		masterA[i] = byte(i + 1)
		masterB[i] = byte(0xA0 + i)
	}

	dek, err := NewDEK()
	if err != nil {
		t.Fatalf("NewDEK: %v", err)
	}

	kekA, err := DeriveKey(masterA, PrincipalOrg, "acme")
	if err != nil {
		t.Fatalf("DeriveKey A: %v", err)
	}
	aad := PrincipalAAD(PrincipalOrg, "acme")
	blobA, err := WrapDEK(kekA, dek, aad)
	if err != nil {
		t.Fatalf("WrapDEK A: %v", err)
	}

	// Unwrap under the same KEK + aad yields the original DEK.
	got, err := UnwrapDEK(kekA, blobA, aad)
	if err != nil {
		t.Fatalf("UnwrapDEK A: %v", err)
	}
	if !bytes.Equal(got, dek) {
		t.Fatal("envelope: unwrapped DEK != original under same KEK")
	}

	// A different KEK must NOT unwrap (GCM tag rejects it) — no partial key.
	kekWrong, _ := DeriveKey(masterB, PrincipalOrg, "acme")
	if _, err := UnwrapDEK(kekWrong, blobA, aad); err == nil {
		t.Fatal("envelope: wrong KEK unwrapped the DEK — isolation broken")
	}

	// V4 defense-in-depth: the SAME KEK but a DIFFERENT principal AAD must NOT
	// unwrap — the blob is cryptographically bound to its principal, so a
	// sidecar lifted onto another principal fails the GCM tag even if a KEK
	// derivation ever collided.
	if _, err := UnwrapDEK(kekA, blobA, PrincipalAAD(PrincipalOrg, "globex")); err == nil {
		t.Fatal("envelope: blob unwrapped under a different principal AAD — principal binding broken")
	}
	if _, err := UnwrapDEK(kekA, blobA, PrincipalAAD(PrincipalGlobal, "acme")); err == nil {
		t.Fatal("envelope: blob unwrapped under a different principal-type AAD — type binding broken")
	}

	// ROTATION: unwrap with old KEK, rewrap with new KEK (same aad). DEK unchanged.
	mid, err := UnwrapDEK(kekA, blobA, aad)
	if err != nil {
		t.Fatalf("rotation unwrap: %v", err)
	}
	kekB, _ := DeriveKey(masterB, PrincipalOrg, "acme")
	blobB, err := WrapDEK(kekB, mid, aad)
	if err != nil {
		t.Fatalf("rewrap B: %v", err)
	}
	rotated, err := UnwrapDEK(kekB, blobB, aad)
	if err != nil {
		t.Fatalf("UnwrapDEK B: %v", err)
	}
	if !bytes.Equal(rotated, dek) {
		t.Fatal("rotation: DEK changed across rewrap — pages would be unreadable (BRICK)")
	}
	// Old blob must no longer unwrap under the new KEK.
	if _, err := UnwrapDEK(kekB, blobA, aad); err == nil {
		t.Fatal("rotation: old blob unwrapped under new KEK — rewrap is not binding")
	}

	// Tamper detection: flip a ciphertext byte, expect failure.
	tampered := append([]byte(nil), blobB...)
	tampered[len(tampered)-1] ^= 0x01
	if _, err := UnwrapDEK(kekB, tampered, aad); err == nil {
		t.Fatal("envelope: tampered blob unwrapped — GCM integrity not enforced")
	}
}

// TestHKDFInfoInjective proves the length-prefixed HKDF info is injective across
// the type/id boundary (finding M5): (org, "a:b") and ("org:a", "b") must derive
// DIFFERENT keys. The old "%s:%s" form collided.
func TestHKDFInfoInjective(t *testing.T) {
	master := make([]byte, 32)
	for i := range master {
		master[i] = byte(i)
	}
	k1, err := DeriveKey(master, PrincipalType("org"), "a:b")
	if err != nil {
		t.Fatalf("derive k1: %v", err)
	}
	k2, err := DeriveKey(master, PrincipalType("org:a"), "b")
	if err != nil {
		t.Fatalf("derive k2: %v", err)
	}
	if bytes.Equal(k1, k2) {
		t.Fatal("HKDF info collision: (org,'a:b') == ('org:a','b') — info not injective")
	}
}

// TestKeyHierarchy proves a per-user KEK is bound to its parent (org) KEK
// (finding M6 primitive): the same user ID under two different org KEKs derives
// different child keys.
func TestKeyHierarchy(t *testing.T) {
	master := make([]byte, 32)
	for i := range master {
		master[i] = byte(i*5 + 2)
	}
	orgA, _ := DeriveKey(master, PrincipalOrg, "acme")
	orgB, _ := DeriveKey(master, PrincipalOrg, "globex")

	userA, err := DeriveChildKey(orgA, PrincipalUser, "u-123")
	if err != nil {
		t.Fatalf("child A: %v", err)
	}
	userB, err := DeriveChildKey(orgB, PrincipalUser, "u-123")
	if err != nil {
		t.Fatalf("child B: %v", err)
	}
	if bytes.Equal(userA, userB) {
		t.Fatal("hierarchy: same user under different orgs derived same key — not org-bound")
	}
}
