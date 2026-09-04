package sqlite

import (
	"bytes"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// TestKeyedRoundTripAndCheckpoint exercises the full keyed lifecycle on whichever
// mechanism this build uses (pure-Go envelope, or the live codec on a cgo build):
// create, write, Checkpoint (mid-session durability), write more, close, reopen,
// read everything back. The real path must be ciphertext AFTER the checkpoint and
// AFTER close — never plaintext at any point a reader could observe it.
func TestKeyedRoundTripAndCheckpoint(t *testing.T) {
	skipIfNoEnvelopeScratch(t)
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i*13 + 7)
	}
	path := filepath.Join(t.TempDir(), "rt.db")

	db, err := OpenDB(path, key)
	if err != nil {
		t.Fatalf("OpenDB: %v", err)
	}
	if _, err := db.Exec(`CREATE TABLE t (id INTEGER PRIMARY KEY, v TEXT)`); err != nil {
		t.Fatalf("create: %v", err)
	}
	if _, err := db.Exec(`INSERT INTO t (v) VALUES ('one')`); err != nil {
		t.Fatalf("insert: %v", err)
	}

	// Checkpoint mid-session: the ciphertext on disk must now be current AND never
	// plaintext.
	if err := Checkpoint(db); err != nil {
		t.Fatalf("checkpoint: %v", err)
	}
	assertCiphertextOnDisk(t, path, "one")

	if _, err := db.Exec(`INSERT INTO t (v) VALUES ('two')`); err != nil {
		t.Fatalf("insert 2: %v", err)
	}
	if err := db.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	assertCiphertextOnDisk(t, path, "two")

	// Reopen and read both rows back.
	db2, err := OpenDB(path, key)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer db2.Close()
	rows, err := db2.Query(`SELECT v FROM t ORDER BY id`)
	if err != nil {
		t.Fatalf("query: %v", err)
	}
	defer rows.Close()
	var got []string
	for rows.Next() {
		var v string
		if err := rows.Scan(&v); err != nil {
			t.Fatal(err)
		}
		got = append(got, v)
	}
	if len(got) != 2 || got[0] != "one" || got[1] != "two" {
		t.Fatalf("read back %v, want [one two]", got)
	}
}

// TestKeyedTempStoreMemory asserts the envelope connection keeps temp b-trees in
// RAM (temp_store=MEMORY) on the pure-Go backend, where the plaintext copy is opened
// by modernc — a temp-file spill there would be decrypted data on disk. Skipped when
// the live libsqlcipher codec is used (it encrypts its own temp spills).
func TestKeyedTempStoreMemory(t *testing.T) {
	if CodecLinked() {
		t.Skip("live libsqlcipher codec encrypts its own temp spills; temp_store is not the guard there")
	}
	skipIfNoEnvelopeScratch(t)
	key := make([]byte, 32)
	db, err := OpenDB(filepath.Join(t.TempDir(), "ts.db"), key)
	if err != nil {
		t.Fatalf("OpenDB: %v", err)
	}
	defer db.Close()
	var ts int
	if err := db.QueryRow("PRAGMA temp_store").Scan(&ts); err != nil {
		t.Fatalf("read temp_store: %v", err)
	}
	if ts != 2 {
		t.Fatalf("temp_store = %d, want 2 (MEMORY)", ts)
	}
}

// TestKeyedWrongKeyRejected proves a wrong key never yields data: the envelope
// fails at DecryptFile (page-1 authentication), the live codec at the query.
func TestKeyedWrongKeyRejected(t *testing.T) {
	skipIfNoEnvelopeScratch(t)
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i + 1)
	}
	path := filepath.Join(t.TempDir(), "wk.db")

	db, err := OpenDB(path, key)
	if err != nil {
		t.Fatalf("OpenDB: %v", err)
	}
	if _, err := db.Exec(`CREATE TABLE s (v TEXT)`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO s VALUES ('classified')`); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}

	wrong := make([]byte, 32)
	copy(wrong, key)
	wrong[0] ^= 0xFF
	db2, err := OpenDB(path, wrong)
	if err == nil {
		var v string
		err = db2.QueryRow(`SELECT v FROM s`).Scan(&v)
		db2.Close()
	}
	if err == nil {
		t.Fatal("wrong key read succeeded — key is not enforced")
	}
}

// TestOpenDBRejectsWrongKeyLength proves OpenDB rejects a non-32-byte key on BOTH
// the live-libsqlcipher path and the envelope path — otherwise SQLCipher would
// silently reinterpret a wrong-length `key=x'HEX'` blob as a passphrase (a
// different, weaker key), and OpenDB (unlike Open) had no length check.
func TestOpenDBRejectsWrongKeyLength(t *testing.T) {
	for _, n := range []int{0, 16, 31, 33, 64} {
		if n == 0 {
			continue // nil-key means unencrypted; a 0-length non-nil key:
		}
		key := make([]byte, n)
		path := filepath.Join(t.TempDir(), "kl.db")
		if _, err := OpenDB(path, key); err == nil {
			t.Fatalf("OpenDB accepted a %d-byte key; must reject non-32", n)
		}
		if _, err := os.Stat(path); !os.IsNotExist(err) {
			t.Fatalf("OpenDB created a file for a rejected %d-byte key", n)
		}
	}
}

// TestEnvelopeFailsClosedWithoutRAMFS proves the confidentiality-critical property:
// when the pure-Go codec envelope cannot get RAM-backed scratch, a keyed open FAILS
// CLOSED and writes NO file — it never decrypts to persistent storage. (The live
// libsqlcipher codec needs no scratch, so this is an envelope-only property.)
func TestEnvelopeFailsClosedWithoutRAMFS(t *testing.T) {
	if CodecLinked() {
		t.Skip("live libsqlcipher codec needs no RAM-backed scratch")
	}
	// Point the resolver at a path that is not RAM-backed (does not exist ⇒ statfs
	// fails ⇒ isRAMBacked false), so ramfsBase must refuse.
	t.Setenv(ramfsEnv, filepath.Join(t.TempDir(), "definitely-not-tmpfs"))

	key := make([]byte, 32)
	path := filepath.Join(t.TempDir(), "fc.db")
	if _, err := OpenDB(path, key); err == nil {
		t.Fatal("keyed open succeeded with no RAM-backed scratch — it must fail closed")
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("a fail-closed keyed open created a file at %s", path)
	}
}

// TestInsecureDevOptOutOpensWithoutRAMFS proves the escape hatch: with
// HANZO_DEV=1 a keyed open succeeds on a host with no RAM-backed scratch, so a
// developer or a test run needs no root to mount tmpfs. The default (no opt-out)
// still fails closed — TestEnvelopeFailsClosedWithoutRAMFS holds that line.
func TestInsecureDevOptOutOpensWithoutRAMFS(t *testing.T) {
	if CodecLinked() {
		t.Skip("live libsqlcipher codec needs no RAM-backed scratch")
	}
	// No RAM-backed dir anywhere: the override is a path that is not tmpfs and does
	// not exist, and /dev/shm is absent on this platform too. Only the opt-out can
	// make the open succeed.
	t.Setenv(ramfsEnv, "")
	t.Setenv(devEnv, "1")

	base, ok := insecureDevScratch()
	if !ok || base == "" {
		t.Fatalf("insecureDevScratch off or empty under HANZO_DEV=1: %q ok=%v", base, ok)
	}

	key := make([]byte, 32)
	path := filepath.Join(t.TempDir(), "dev.db")
	db, err := OpenDB(path, key)
	if err != nil {
		t.Fatalf("keyed open under the opt-out failed: %v", err)
	}
	db.Close()
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("the encrypted file was not written at %s: %v", path, err)
	}
}

// TestRefusalNamesTheRemedy: failing closed is the safety property; naming the fix
// is what stops it reading as "your platform is unsupported".
func TestRefusalNamesTheRemedy(t *testing.T) {
	if CodecLinked() {
		t.Skip("live libsqlcipher codec needs no RAM-backed scratch")
	}
	notRAM := filepath.Join(t.TempDir(), "definitely-not-tmpfs")

	// Both roads out of ramfsBase must carry the hint: the override that does not
	// qualify, and no override at all on a host with no /dev/shm.
	t.Setenv(ramfsEnv, notRAM)
	_, err := ramfsBase()
	if err == nil {
		t.Fatal("a non-RAM-backed override was accepted")
	}
	assertHint(t, err)

	t.Setenv(ramfsEnv, "")
	if _, err := ramfsBase(); err != nil {
		// Only assert on hosts that actually lack /dev/shm; where one exists this
		// path legitimately succeeds and there is nothing to teach.
		assertHint(t, err)
	}
}

// assertHint requires the COMMAND, not prose. "needs tmpfs" and stop is the failure
// this guards.
func assertHint(t *testing.T, err error) {
	t.Helper()
	if ramfsHint == "" {
		return // a platform where this package knows no verified road
	}
	want := "mount_tmpfs"
	if runtime.GOOS == "linux" {
		want = "/dev/shm"
	}
	if !strings.Contains(err.Error(), want) {
		t.Fatalf("refusal does not name the remedy (%q missing):\n%v", want, err)
	}
}

// assertCiphertextOnDisk fails if the file at path is readable as plaintext SQLite
// or contains the marker in the clear — the confidentiality invariant a keyed store
// must always satisfy at rest.
func assertCiphertextOnDisk(t *testing.T, path, marker string) {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	if bytes.HasPrefix(raw, []byte("SQLite format 3\x00")) {
		t.Fatalf("CONFIDENTIALITY VIOLATION: %s has a plaintext SQLite header", path)
	}
	if bytes.Contains(raw, []byte(marker)) {
		t.Fatalf("CONFIDENTIALITY VIOLATION: %q is visible in the clear in %s", marker, path)
	}
}
