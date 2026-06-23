// Per-principal key derivation and envelope wrapping.
//
// ENVELOPE MODEL (read before changing — this is what makes master-key
// rotation non-destructive):
//
//  1. Each database gets its OWN random 256-bit Data Encryption Key (DEK),
//     generated once at creation by NewDEK(). SQLCipher encrypts the file
//     pages with this DEK and only this DEK — it never changes for the life
//     of the file, so the ciphertext pages are never rewritten.
//  2. The DEK is wrapped (AES-256-GCM) under a Key Encryption Key (KEK)
//     derived from the KMS master key:
//     KEK = HKDF-SHA256(masterKey, info = lp(principalType) || lp(id))
//     The wrapped DEK is stored beside the database (a small sidecar blob);
//     the raw DEK is never written to disk.
//  3. Opening: unwrap the stored DEK with the KEK, open SQLCipher with the DEK.
//  4. Master-key ROTATION: unwrap the DEK with the OLD KEK, rewrap it with the
//     NEW KEK, atomically replace the sidecar. The DEK is unchanged, so the
//     encrypted pages are untouched — rotation is O(1) per database and cannot
//     brick a file. (The legacy "derive the page key directly from the master"
//     scheme made rotation impossible: a new master changed the page key and
//     SQLCipher's HMAC rejected every existing file. Envelope dissolves that.)
//
// `lp(x)` is the length-prefixed encoding of x (uvarint length || bytes). It is
// injective, so two principals can never collide across the type/id boundary
// (e.g. type "org"+id "a:b" and type "org:a"+id "b" hash differently — the old
// "%s:%s" form did not guarantee this).
package sqlite

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"io"

	"golang.org/x/crypto/hkdf"
)

// PrincipalType identifies the type of principal for key derivation. It forms
// the domain-separation tag of the derived KEK.
type PrincipalType string

const (
	// PrincipalGlobal is the cross-org global/platform database (certs,
	// providers, the admin org catalog). Distinct from any org named "global".
	PrincipalGlobal PrincipalType = "global"
	PrincipalOrg    PrincipalType = "org"
	PrincipalUser   PrincipalType = "user"
)

// dekLen is the length of a Data Encryption Key (SQLCipher AES-256).
const dekLen = 32

// wrapVersion is the on-disk wrapped-DEK format version. Byte 0 of a wrapped
// blob. Bump only if the wrapping scheme changes.
const wrapVersion = 1

// lengthPrefixedInfo builds an injective HKDF `info` from (principalType, id):
//
//	uvarint(len(type)) || type || uvarint(len(id)) || id
//
// Injectivity guarantees domain separation across the type/id boundary.
func lengthPrefixedInfo(principalType PrincipalType, principalID string) []byte {
	t := []byte(principalType)
	id := []byte(principalID)
	out := make([]byte, 0, binary.MaxVarintLen64*2+len(t)+len(id))
	var tmp [binary.MaxVarintLen64]byte
	n := binary.PutUvarint(tmp[:], uint64(len(t)))
	out = append(out, tmp[:n]...)
	out = append(out, t...)
	n = binary.PutUvarint(tmp[:], uint64(len(id)))
	out = append(out, tmp[:n]...)
	out = append(out, id...)
	return out
}

// DeriveKey derives a 256-bit key for a principal from a master key using
// HKDF-SHA256 with a length-prefixed, injective `info`.
//
// In the envelope model this is the KEK (it WRAPS a per-database DEK); it is no
// longer used as a SQLCipher page key directly. Callers that need a page key use
// NewDEK + WrapDEK/UnwrapDEK.
//
//	masterKey:     32-byte master encryption key (from KMS)
//	principalType: "global", "org", or "user"
//	principalID:   unique identifier (org slug, user ID, "iam" for global)
func DeriveKey(masterKey []byte, principalType PrincipalType, principalID string) ([]byte, error) {
	if len(masterKey) != 32 {
		return nil, fmt.Errorf("sqlite/cek: master key must be 32 bytes, got %d", len(masterKey))
	}
	if principalID == "" {
		return nil, fmt.Errorf("sqlite/cek: principal ID cannot be empty")
	}

	r := hkdf.New(sha256.New, masterKey, nil, lengthPrefixedInfo(principalType, principalID))
	kek := make([]byte, 32)
	if _, err := io.ReadFull(r, kek); err != nil {
		return nil, fmt.Errorf("sqlite/cek: hkdf: %w", err)
	}
	return kek, nil
}

// DeriveChildKey derives a child KEK from a PARENT key (not the master),
// establishing a key hierarchy: master → per-org KEK → per-user KEK. A per-user
// database's DEK is therefore wrapped under a KEK that is itself bound to the
// org, so compromising the master alone is not sufficient without traversing the
// hierarchy, and an org's user keys are cryptographically contained within that
// org.
//
//	parentKey:     32-byte parent key (e.g. the org KEK from DeriveKey)
//	principalType: child principal type (typically PrincipalUser)
//	principalID:   child identifier (user ID)
func DeriveChildKey(parentKey []byte, principalType PrincipalType, principalID string) ([]byte, error) {
	// Identical KDF as DeriveKey; the distinction is the secret input is a
	// parent KEK rather than the master, which is what makes the hierarchy.
	return DeriveKey(parentKey, principalType, principalID)
}

// NewDEK generates a fresh random 256-bit Data Encryption Key. Each database is
// created with exactly one DEK, which never changes for the life of the file.
func NewDEK() ([]byte, error) {
	dek := make([]byte, dekLen)
	if _, err := rand.Read(dek); err != nil {
		return nil, fmt.Errorf("sqlite/cek: generate DEK: %w", err)
	}
	return dek, nil
}

// WrapDEK seals a DEK under a KEK with AES-256-GCM and returns the storable
// blob: version(1) || nonce(12) || ciphertext||tag. The KEK must be 32 bytes
// (as produced by DeriveKey / DeriveChildKey). The blob is safe to store
// next to the database; it reveals nothing about the DEK without the KEK.
func WrapDEK(kek, dek []byte) ([]byte, error) {
	if len(kek) != 32 {
		return nil, fmt.Errorf("sqlite/cek: KEK must be 32 bytes, got %d", len(kek))
	}
	if len(dek) != dekLen {
		return nil, fmt.Errorf("sqlite/cek: DEK must be %d bytes, got %d", dekLen, len(dek))
	}
	gcm, err := newGCM(kek)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("sqlite/cek: generate nonce: %w", err)
	}
	// AAD binds the version so a downgrade can't be forged.
	out := make([]byte, 0, 1+len(nonce)+len(dek)+gcm.Overhead())
	out = append(out, wrapVersion)
	out = append(out, nonce...)
	out = gcm.Seal(out, nonce, dek, []byte{wrapVersion})
	return out, nil
}

// UnwrapDEK opens a blob produced by WrapDEK under the same KEK. A wrong KEK,
// truncated blob, or tampered ciphertext fails the GCM tag and returns an error
// — never a partial/garbage key.
func UnwrapDEK(kek, blob []byte) ([]byte, error) {
	if len(kek) != 32 {
		return nil, fmt.Errorf("sqlite/cek: KEK must be 32 bytes, got %d", len(kek))
	}
	gcm, err := newGCM(kek)
	if err != nil {
		return nil, err
	}
	ns := gcm.NonceSize()
	if len(blob) < 1+ns+gcm.Overhead() {
		return nil, fmt.Errorf("sqlite/cek: wrapped DEK too short (%d bytes)", len(blob))
	}
	if blob[0] != wrapVersion {
		return nil, fmt.Errorf("sqlite/cek: unsupported wrapped-DEK version %d", blob[0])
	}
	nonce := blob[1 : 1+ns]
	ct := blob[1+ns:]
	dek, err := gcm.Open(nil, nonce, ct, []byte{wrapVersion})
	if err != nil {
		return nil, fmt.Errorf("sqlite/cek: unwrap DEK (wrong key or corrupt blob): %w", err)
	}
	if len(dek) != dekLen {
		return nil, fmt.Errorf("sqlite/cek: unwrapped DEK has wrong length %d", len(dek))
	}
	return dek, nil
}

func newGCM(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("sqlite/cek: aes cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("sqlite/cek: gcm: %w", err)
	}
	return gcm, nil
}

// WithPrincipalKey derives a KEK, generates/uses a DEK, and configures the
// database to use the page key. Retained for the standalone Open() helper path;
// the envelope sidecar lifecycle (which is what production IAM uses) is driven
// by the consumer (object/orgdb.go) via NewDEK + WrapDEK/UnwrapDEK + OpenDB.
//
// Deprecated for the lifecycle path: this derives a page key directly and so is
// NOT rotation-safe. Use the envelope helpers for any persistent database.
func WithPrincipalKey(masterKey []byte, principalType PrincipalType, principalID string) Option {
	return func(c *Config) {
		kek, err := DeriveKey(masterKey, principalType, principalID)
		if err != nil {
			c.derivationErr = err
			return
		}
		c.RawKey = kek
	}
}
