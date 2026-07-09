// Envelope-aware open: ONE call that gives a consumer at-rest encryption when a
// master key is present and unchanged plaintext behaviour when it is not.
//
// This is the seam every cloud subsystem store should open through instead of a
// bare `sql.Open("sqlite", path)`. It resolves the four states a data file can be
// in — enveloped (sidecar present), fresh (absent/empty), pre-existing plaintext,
// or lost-sidecar ciphertext — so callers do not each reimplement (and diverge
// on) the envelope + migration logic. It is the runtime twin of
// MigrateFileToEncrypted: the migration WRITES the enveloped layout, OpenEnveloped
// READS it (and self-heals a plaintext file into it on first open).
package sqlite

import (
	"bytes"
	"database/sql"
	"fmt"
	"os"
)

// OpenEnveloped opens path as a *sql.DB with at-rest encryption governed by
// masterKey:
//
//   - masterKey empty (len 0) → PLAINTEXT: identical to sql.Open("sqlite", path).
//     This is the dev / no-key posture; the returned DB is byte-for-byte what a
//     bare open would produce, so callers that apply their own pragmas afterwards
//     are unaffected.
//   - masterKey set (32 bytes) → ENCRYPTED. The per-file DEK is unwrapped from the
//     `<path>.dek` sidecar under KEK=DeriveKey(masterKey, pt, id); the file is
//     opened via SQLCipher with that DEK. Posture is fail-secure: a build that
//     cannot encrypt (pure-Go, or cgo without the codec linked) returns an error
//     rather than silently open plaintext.
//
// State handling when masterKey is set:
//
//	sidecar present                      → unwrap DEK, open encrypted (fast path).
//	no sidecar, file absent/empty        → mint a DEK, write the sidecar, create
//	                                       a fresh ENCRYPTED file.
//	no sidecar, file is plaintext        → SELF-HEAL: migrate it to enveloped
//	                                       (MigrateFileToEncrypted, atomic, keeps
//	                                       `<path>.plaintext.bak`), then open it.
//	no sidecar, file is already ciphertext → refuse (the DEK is unrecoverable) —
//	                                       never clobber money data as if fresh.
//
// pt/id identify the principal for KEK derivation (e.g. PrincipalGlobal + the
// db's stable name). The SAME (pt,id) must be used every open, or the sidecar's
// GCM AAD check fails.
func OpenEnveloped(path string, masterKey []byte, pt PrincipalType, id string) (*sql.DB, error) {
	if len(masterKey) == 0 {
		return sql.Open("sqlite", path) // plaintext posture, unchanged behaviour
	}
	if len(masterKey) != 32 {
		return nil, fmt.Errorf("sqlite/enveloped: master key must be 32 bytes, got %d", len(masterKey))
	}
	// Key set but this build cannot encrypt → fail secure, never write plaintext.
	if !EncryptionAvailable() {
		return nil, fmt.Errorf("sqlite/enveloped: master key set but this build cannot encrypt (pure-Go sqlite): %w", ErrEncryptionUnavailable)
	}
	if !CodecLinked() {
		return nil, fmt.Errorf("sqlite/enveloped: master key set but libsqlcipher is NOT linked (CodecLinked()=false) — refusing to open %q as plaintext", path)
	}

	kek, err := DeriveKey(masterKey, pt, id)
	if err != nil {
		return nil, fmt.Errorf("sqlite/enveloped: derive KEK: %w", err)
	}
	defer zeroBytes(kek)
	aad := PrincipalAAD(pt, id)
	dekPath := path + dekSuffix

	// Fast path: sidecar present → unwrap → open encrypted.
	if fileExists(dekPath) {
		return openWithSidecar(path, dekPath, kek, aad)
	}

	// No sidecar. Decide by the data file's state.
	if !fileNonEmpty(path) {
		// Absent or zero-length → genuinely fresh: mint a DEK, persist the sidecar,
		// create the encrypted file. O_EXCL on the sidecar closes the (single-writer)
		// first-touch race: a loser finds the winner's sidecar and reuses it.
		return createFreshEncrypted(path, dekPath, kek, aad)
	}

	plain, err := isPlaintextSQLiteFile(path)
	if err != nil {
		return nil, fmt.Errorf("sqlite/enveloped: inspect %q: %w", path, err)
	}
	if !plain {
		return nil, fmt.Errorf("sqlite/enveloped: %q is encrypted but has no %s sidecar — refusing (its DEK is unrecoverable)", path, dekSuffix)
	}

	// Pre-existing plaintext + master key present → self-heal to enveloped, then open.
	if _, _, err := MigrateFileToEncrypted(path, masterKey, pt, id); err != nil {
		return nil, fmt.Errorf("sqlite/enveloped: migrate plaintext %q to encrypted: %w", path, err)
	}
	return openWithSidecar(path, dekPath, kek, aad)
}

// openWithSidecar unwraps the DEK from an existing sidecar and opens path
// encrypted. A wrong master key, a sidecar from another principal, or a tampered
// blob fails the GCM tag here (never a partial/garbage key).
func openWithSidecar(path, dekPath string, kek, aad []byte) (*sql.DB, error) {
	blob, err := os.ReadFile(dekPath)
	if err != nil {
		return nil, fmt.Errorf("sqlite/enveloped: read sidecar %q: %w", dekPath, err)
	}
	dek, err := UnwrapDEK(kek, blob, aad)
	if err != nil {
		return nil, fmt.Errorf("sqlite/enveloped: unwrap DEK for %q (wrong master key or corrupt sidecar): %w", path, err)
	}
	defer zeroBytes(dek)
	return OpenDB(path, dek)
}

// createFreshEncrypted mints a DEK, writes the sidecar with O_EXCL, and opens a
// fresh encrypted file. If another writer created the sidecar first (EEXIST), it
// reuses that one — so a first-touch race can never mint divergent DEKs.
func createFreshEncrypted(path, dekPath string, kek, aad []byte) (*sql.DB, error) {
	dek, err := NewDEK()
	if err != nil {
		return nil, fmt.Errorf("sqlite/enveloped: mint DEK: %w", err)
	}
	defer zeroBytes(dek)
	blob, err := WrapDEK(kek, dek, aad)
	if err != nil {
		return nil, fmt.Errorf("sqlite/enveloped: wrap DEK: %w", err)
	}
	f, err := os.OpenFile(dekPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		if os.IsExist(err) {
			// Lost the race — a concurrent open wrote the sidecar. Use it.
			return openWithSidecar(path, dekPath, kek, aad)
		}
		return nil, fmt.Errorf("sqlite/enveloped: create sidecar %q: %w", dekPath, err)
	}
	if _, err := f.Write(blob); err != nil {
		f.Close()
		_ = os.Remove(dekPath)
		return nil, fmt.Errorf("sqlite/enveloped: write sidecar %q: %w", dekPath, err)
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(dekPath)
		return nil, fmt.Errorf("sqlite/enveloped: close sidecar %q: %w", dekPath, err)
	}
	return OpenDB(path, dek)
}

// isPlaintextSQLiteFile reports whether path begins with the plaintext SQLite
// header. A SQLCipher-encrypted file has an encrypted (random-looking) first
// page, so the absence of this magic distinguishes ciphertext from plaintext.
func isPlaintextSQLiteFile(path string) (bool, error) {
	f, err := os.Open(path)
	if err != nil {
		return false, err
	}
	defer f.Close()
	var hdr [16]byte
	n, err := f.Read(hdr[:])
	if err != nil && n == 0 {
		return false, err
	}
	return bytes.HasPrefix(hdr[:n], []byte("SQLite format 3\x00")), nil
}

// fileExists reports whether path exists (any type).
func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

// fileNonEmpty reports whether path exists and has a non-zero size.
func fileNonEmpty(path string) bool {
	fi, err := os.Stat(path)
	return err == nil && fi.Size() > 0
}

// writeFileAtomic writes data to a temp file in the same directory and renames it
// into place, so a crash never leaves a half-written file.
func writeFileAtomic(path string, data []byte, perm os.FileMode) error {
	tmp, err := os.CreateTemp(dirOf(path), ".tmp-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		_ = os.Remove(tmpName)
		return err
	}
	if err := tmp.Chmod(perm); err != nil {
		tmp.Close()
		_ = os.Remove(tmpName)
		return err
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmpName)
		return err
	}
	return os.Rename(tmpName, path)
}

// dirOf returns the directory of path (".", never empty, for a bare filename).
func dirOf(path string) string {
	for i := len(path) - 1; i >= 0; i-- {
		if path[i] == '/' {
			if i == 0 {
				return "/"
			}
			return path[:i]
		}
	}
	return "."
}

// zeroBytes wipes a key buffer after use.
func zeroBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
