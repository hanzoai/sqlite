// Per-principal CEK derivation via HKDF.
//
// Each org/user gets a unique 256-bit Content Encryption Key derived from:
//
//	CEK = HKDF-SHA256(master_key, principal_id)
//
// This ensures:
//   - Different orgs can't read each other's databases
//   - Master key compromise + principal ID needed to derive any CEK
//   - Key rotation: re-derive all CEKs from new master, re-encrypt databases
package sqlite

import (
	"crypto/sha256"
	"fmt"
	"io"

	"golang.org/x/crypto/hkdf"
)

// PrincipalType identifies the type of principal for CEK derivation.
type PrincipalType string

const (
	PrincipalOrg  PrincipalType = "org"
	PrincipalUser PrincipalType = "user"
)

// DeriveKey derives a 256-bit CEK for a principal from a master key using HKDF-SHA256.
//
//	masterKey: 32-byte master encryption key (from KMS)
//	principalType: "org" or "user"
//	principalID: unique identifier (org slug, user ID)
//
// The info string is "{principalType}:{principalID}" ensuring domain separation.
func DeriveKey(masterKey []byte, principalType PrincipalType, principalID string) ([]byte, error) {
	if len(masterKey) != 32 {
		return nil, fmt.Errorf("sqlite/cek: master key must be 32 bytes, got %d", len(masterKey))
	}
	if principalID == "" {
		return nil, fmt.Errorf("sqlite/cek: principal ID cannot be empty")
	}

	info := []byte(fmt.Sprintf("%s:%s", principalType, principalID))
	r := hkdf.New(sha256.New, masterKey, nil, info)

	cek := make([]byte, 32)
	if _, err := io.ReadFull(r, cek); err != nil {
		return nil, fmt.Errorf("sqlite/cek: hkdf: %w", err)
	}
	return cek, nil
}

// WithPrincipalKey derives a CEK and configures the database to use it.
// This is the primary API for per-org and per-user encryption.
func WithPrincipalKey(masterKey []byte, principalType PrincipalType, principalID string) Option {
	return func(c *Config) {
		cek, err := DeriveKey(masterKey, principalType, principalID)
		if err != nil {
			c.derivationErr = err
			return
		}
		c.RawKey = cek
	}
}
