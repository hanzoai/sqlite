package sqlite

import (
	"bytes"
	"encoding/hex"
	"testing"
)

// GOLDEN FORMAT FIXTURE — the regression gate for the AEAD backend swap.
//
// These bytes were produced by the PRE-swap stdlib (crypto/aes + crypto/cipher)
// WrapDEK path with fixed inputs (masterKey = 0x00..0x1f, principal = org/acme,
// DEK = 0xff..0xe0, nonce = 0xA0..0xAB). Every deployed IAM `.dek` sidecar has
// this exact on-disk shape: version(1) ‖ nonce(12) ‖ AES-256-GCM(DEK)‖tag(16) =
// 61 bytes, with GCM AAD = version ‖ PrincipalAAD(type,id).
//
// The swap of WrapDEK/UnwrapDEK's AEAD from stdlib to luxfi/crypto/aead is only
// safe if the POST-swap UnwrapDEK still decrypts this PRE-swap blob to the exact
// DEK. If it ever fails, the swap diverged from standard NIST AES-256-GCM and
// would brick every existing encrypted store (fail-closed at UnwrapDEK) — DO NOT
// "fix" the fixture; fix the code. The KEK derivation (HKDF-SHA256, unchanged)
// is exercised via the real DeriveKey below, so this also guards the KEK.
const (
	goldenMasterKeyHex = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
	goldenDEKHex       = "fffefdfcfbfaf9f8f7f6f5f4f3f2f1f0efeeedecebeae9e8e7e6e5e4e3e2e1e0"
	goldenBlobHex      = "01a0a1a2a3a4a5a6a7a8a9aaabee3138a75c8b488cf0ac2bdd7f1b43ec0be58653540396f0685b7f95ce1a9fab16fb11adfa1d4717bb1b873b0d38b077"
	goldenPrincipalID  = "acme"
)

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("bad hex fixture: %v", err)
	}
	return b
}

// TestUnwrapGoldenFixture is the format-equivalence gate: the current
// UnwrapDEK (whatever AEAD backend it uses) MUST decrypt the frozen pre-swap
// sidecar to the exact DEK, using a KEK re-derived from the master key via the
// live DeriveKey. This is what proves existing encrypted stores stay readable.
func TestUnwrapGoldenFixture(t *testing.T) {
	master := mustHex(t, goldenMasterKeyHex)
	wantDEK := mustHex(t, goldenDEKHex)
	blob := mustHex(t, goldenBlobHex)

	if len(blob) != 61 {
		t.Fatalf("golden blob is %d bytes, want 61 (version1+nonce12+ct32+tag16)", len(blob))
	}
	if blob[0] != wrapVersion {
		t.Fatalf("golden blob version byte = %d, want %d", blob[0], wrapVersion)
	}

	kek, err := DeriveKey(master, PrincipalOrg, goldenPrincipalID)
	if err != nil {
		t.Fatalf("DeriveKey: %v", err)
	}
	aad := PrincipalAAD(PrincipalOrg, goldenPrincipalID)

	gotDEK, err := UnwrapDEK(kek, blob, aad)
	if err != nil {
		t.Fatalf("UnwrapDEK of golden fixture failed — AEAD backend diverged from standard AES-256-GCM, existing stores would brick: %v", err)
	}
	if !bytes.Equal(gotDEK, wantDEK) {
		t.Fatalf("golden DEK mismatch:\n got %x\nwant %x", gotDEK, wantDEK)
	}

	// The wrong principal AAD must fail the GCM tag (binding preserved).
	if _, err := UnwrapDEK(kek, blob, PrincipalAAD(PrincipalOrg, "other")); err == nil {
		t.Fatal("golden blob unwrapped under the wrong principal AAD — binding lost")
	}
}

// TestWrapUnwrapRoundTripPinsLayout pins the byte layout the swap must preserve:
// a freshly wrapped DEK is exactly 61 bytes, version-prefixed, and unwraps back
// to the same DEK under the same KEK+AAD.
func TestWrapUnwrapRoundTripPinsLayout(t *testing.T) {
	master := mustHex(t, goldenMasterKeyHex)
	kek, err := DeriveKey(master, PrincipalOrg, "roundtrip")
	if err != nil {
		t.Fatalf("DeriveKey: %v", err)
	}
	dek, err := NewDEK()
	if err != nil {
		t.Fatalf("NewDEK: %v", err)
	}
	aad := PrincipalAAD(PrincipalOrg, "roundtrip")

	blob, err := WrapDEK(kek, dek, aad)
	if err != nil {
		t.Fatalf("WrapDEK: %v", err)
	}
	if len(blob) != 61 {
		t.Fatalf("wrapped blob is %d bytes, want 61", len(blob))
	}
	if blob[0] != wrapVersion {
		t.Fatalf("wrapped blob version = %d, want %d", blob[0], wrapVersion)
	}

	got, err := UnwrapDEK(kek, blob, aad)
	if err != nil {
		t.Fatalf("UnwrapDEK round-trip: %v", err)
	}
	if !bytes.Equal(got, dek) {
		t.Fatalf("round-trip DEK mismatch:\n got %x\nwant %x", got, dek)
	}
}
