//go:build cgo && !sqlite_purego

package sqlite

import (
	"bytes"
	"database/sql"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
)

// dbHandle is satisfied by both *DB (from Open, which embeds *sql.DB) and *sql.DB
// (from OpenDB), so one test body covers both keyed entry points.
type dbHandle interface {
	Exec(query string, args ...any) (sql.Result, error)
	QueryRow(query string, args ...any) *sql.Row
	Close() error
}

// TestBrokenLibsqlcipherFallsBackToEnvelope simulates the confidentiality bug and
// proves the always-encrypt fix. A cgo build whose linked SQLite is NOT SQLCipher
// silently no-ops PRAGMA key and writes PLAINTEXT. Forcing the codec probe to report
// that broken state must NOT dead-end and must NOT write plaintext: openDB falls
// back to the pure-Go SQLCipher codec envelope, so a keyed store is still encrypted.
//
// It exercises BOTH Open and OpenDB (the entry cek uses): both must produce
// ciphertext on disk that round-trips under the key.
func TestBrokenLibsqlcipherFallsBackToEnvelope(t *testing.T) {
	skipIfNoEnvelopeScratch(t)
	atomic.StoreInt32(&probeOverride, 2) // 2 = force "C codec broken"
	defer atomic.StoreInt32(&probeOverride, 0)

	if CodecLinked() {
		t.Fatal("forced probe not honored: CodecLinked() must be false")
	}
	if !EncryptionAvailable() {
		t.Fatal("EncryptionAvailable() must stay true — the pure-Go codec is always available")
	}

	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i + 9)
	}
	const marker = "envelope-fallback-marker-4c1a"

	for _, tc := range []struct {
		name string
		open func(path string) (dbHandle, error)
	}{
		{"Open", func(p string) (dbHandle, error) { return Open(p, WithRawKey(key)) }},
		{"OpenDB", func(p string) (dbHandle, error) { return OpenDB(p, key) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "fb.db")
			h, err := tc.open(path)
			if err != nil {
				t.Fatalf("%s with key on a broken-codec build: %v", tc.name, err)
			}
			if _, err := h.Exec(`CREATE TABLE c (v TEXT)`); err != nil {
				t.Fatalf("create: %v", err)
			}
			if _, err := h.Exec(`INSERT INTO c VALUES (?)`, marker); err != nil {
				t.Fatalf("insert: %v", err)
			}
			if err := h.Close(); err != nil {
				t.Fatalf("close (seal): %v", err)
			}
			raw, err := os.ReadFile(path)
			if err != nil {
				t.Fatalf("read: %v", err)
			}
			if bytes.HasPrefix(raw, []byte("SQLite format 3\x00")) {
				t.Fatal("FALLBACK FAILURE: broken-codec keyed open wrote a plaintext header")
			}
			if bytes.Contains(raw, []byte(marker)) {
				t.Fatal("FALLBACK FAILURE: marker visible in the clear — not encrypted")
			}
			// Round-trip: reopen (still forced broken → envelope) and read it back.
			h2, err := tc.open(path)
			if err != nil {
				t.Fatalf("reopen: %v", err)
			}
			defer h2.Close()
			var got string
			if err := h2.QueryRow(`SELECT v FROM c`).Scan(&got); err != nil {
				t.Fatalf("round-trip read: %v", err)
			}
			if got != marker {
				t.Fatalf("round-trip read = %q, want %q", got, marker)
			}
		})
	}
}

// TestEnvelopeByteCompatWithLibsqlcipher proves, in ONE binary, that the pure-Go
// codec envelope and the live libsqlcipher codec produce and read each other's
// files — the byte-compatibility the whole design rests on. It writes with one
// mechanism (toggling the probe) and reads with the other, both directions. It runs
// only when libsqlcipher is actually linked.
func TestEnvelopeByteCompatWithLibsqlcipher(t *testing.T) {
	if !CodecLinked() {
		t.Skip("no live libsqlcipher in this build; cannot cross-check the two mechanisms")
	}
	skipIfNoEnvelopeScratch(t)
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i*7 + 2)
	}

	// --- envelope writes → live libsqlcipher reads ---
	t.Run("envelope_write_live_read", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "e2l.db")
		atomic.StoreInt32(&probeOverride, 2) // force envelope
		db, err := OpenDB(path, key)
		if err != nil {
			atomic.StoreInt32(&probeOverride, 0)
			t.Fatalf("envelope OpenDB: %v", err)
		}
		db.Exec(`CREATE TABLE t (v TEXT)`)
		db.Exec(`INSERT INTO t VALUES ('from-envelope')`)
		db.Close()
		atomic.StoreInt32(&probeOverride, 0) // live libsqlcipher now

		db2, err := OpenDB(path, key)
		if err != nil {
			t.Fatalf("live-codec reopen of an envelope-written file: %v", err)
		}
		defer db2.Close()
		var v string
		if err := db2.QueryRow(`SELECT v FROM t`).Scan(&v); err != nil {
			t.Fatalf("live libsqlcipher could not read the envelope's file: %v", err)
		}
		if v != "from-envelope" {
			t.Fatalf("read %q, want from-envelope", v)
		}
	})

	// --- live libsqlcipher writes → envelope reads ---
	t.Run("live_write_envelope_read", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "l2e.db")
		db, err := OpenDB(path, key) // probe=0 ⇒ live codec
		if err != nil {
			t.Fatalf("live OpenDB: %v", err)
		}
		db.Exec(`CREATE TABLE t (v TEXT)`)
		db.Exec(`INSERT INTO t VALUES ('from-libsqlcipher')`)
		db.Close()

		atomic.StoreInt32(&probeOverride, 2) // force envelope
		defer atomic.StoreInt32(&probeOverride, 0)
		db2, err := OpenDB(path, key)
		if err != nil {
			t.Fatalf("envelope reopen of a libsqlcipher-written file: %v", err)
		}
		defer db2.Close()
		var v string
		if err := db2.QueryRow(`SELECT v FROM t`).Scan(&v); err != nil {
			t.Fatalf("the envelope could not read libsqlcipher's file: %v", err)
		}
		if v != "from-libsqlcipher" {
			t.Fatalf("read %q, want from-libsqlcipher", v)
		}
	})
}

// TestProbeTruePositive asserts that when the probe reports the live libsqlcipher
// codec (linked), a keyed OpenDB writes ciphertext via that path. It skips when
// this build has no live codec (the envelope path is covered above).
func TestProbeTruePositive(t *testing.T) {
	if !CodecLinked() {
		t.Skip("no live libsqlcipher in this build; live-codec path not exercisable")
	}
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i*11 + 3)
	}
	path := filepath.Join(t.TempDir(), "tp.db")
	db, err := OpenDB(path, key)
	if err != nil {
		t.Fatalf("OpenDB with key on a live-codec build: %v", err)
	}
	const marker = "true-positive-marker-2d7e"
	if _, err := db.Exec(`CREATE TABLE t (v TEXT)`); err != nil {
		t.Fatalf("create: %v", err)
	}
	if _, err := db.Exec(`INSERT INTO t VALUES (?)`, marker); err != nil {
		t.Fatalf("insert: %v", err)
	}
	if err := db.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if !encryptsAtRest(raw, []byte(marker)) {
		t.Fatal("live-codec keyed OpenDB wrote plaintext")
	}
}
