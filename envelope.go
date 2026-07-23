package sqlite

// The pure-Go SQLCipher envelope — the encryption path that works on EVERY build,
// with no dependency on the C libsqlcipher.
//
// WHY AN ENVELOPE. SQLCipher's codec is a hook inside SQLite's pager, not the VFS,
// and it encrypts WAL frames and rollback-journal records whose checksums SQLite
// computes over the ciphertext (see github.com/hanzoai/sqlcipher LLM.md). A pure-Go
// engine (modernc) has no writable codec hook, so there is no way to encrypt pages
// live from Go. What IS possible — and byte-compatible — is to encrypt the whole
// file: hanzoai/sqlcipher reads and writes the exact SQLCipher 4 page format, in
// both directions, verified against the C library. The envelope uses that:
//
//	Open : DECRYPT the on-disk SQLCipher file to a plaintext copy in RAM (tmpfs),
//	       or, for a new database, seed the RAM copy with sqlcipher.EmptyPlaintext.
//	       The database/sql engine (modernc on pure-Go, csqlite on cgo) opens that
//	       plaintext copy — it never sees a key, and honours the 80-byte reserve the
//	       seed/decrypt carries in the header, so every page it writes leaves room
//	       for the SQLCipher IV+HMAC trailer.
//	Close/Checkpoint : ENCRYPT the plaintext copy back to the real path with the
//	       codec, under the file's salt, atomically. The real path is ALWAYS
//	       SQLCipher ciphertext; a keyed store is never written in the clear.
//
// This is why native Go always encrypts: the codec is always compiled in, so there
// is no build where a keyed store falls back to plaintext.
//
// PROPERTIES AND LIMITS (read before relying on it in a new place):
//
//   - CONFIDENTIALITY AT REST: the real path holds only SQLCipher ciphertext. The
//     decrypted copy lives on a RAM-backed filesystem (tmpfs/ramfs) and is shredded
//     on close; if no RAM-backed scratch dir exists the open FAILS CLOSED rather
//     than decrypt to persistent storage (ramfsBase).
//   - DURABILITY is at Close (and at Checkpoint): writes reach the encrypted file
//     when the handle is checkpointed or closed, not per-commit. A crash loses
//     writes since the last checkpoint/close (the encrypted file keeps its last
//     sealed state). Call Checkpoint to bound that window.
//   - SINGLE WRITER per file: the plaintext copy is private to this handle, so two
//     concurrent envelope opens of the same path do not see each other's writes
//     (last close wins). The intended use is one writer per file (HIP-0302).
//   - The caller MUST Close the handle; otherwise the RAM copy lingers until reboot.

import (
	"context"
	"crypto/rand"
	"database/sql"
	"database/sql/driver"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"

	"github.com/hanzoai/sqlcipher"
)

// ramfsEnv is an optional operator override naming a RAM-backed directory for the
// transient plaintext copy (e.g. a Kubernetes emptyDir{medium:Memory} mount). When
// unset, /dev/shm is used. It is never a switch that disables encryption — only a
// choice of which RAM-backed mount to decrypt into.
const ramfsEnv = "HANZO_SQLITE_RAMFS_DIR"

// envelope holds the state binding one open plaintext copy to its encrypted file.
type envelope struct {
	realPath  string // the on-disk SQLCipher (ciphertext) file
	tmpDir    string // the RAM-backed dir holding the plaintext copy (RemoveAll on shred)
	plainPath string // the decrypted plaintext database (tmpDir/db)
	salt      []byte // the file's 16-byte SQLCipher salt (existing file's, or fresh)
	key       []byte // the 32-byte page key (DEK); zeroed on shred

	db     *sql.DB // back-reference for the checkpoint registry
	mu     sync.Mutex
	sealed bool
}

// liveEnvelopes maps an open *sql.DB to its envelope so Checkpoint can re-encrypt
// the OpenDB path (which returns a bare *sql.DB) mid-session. Entries are removed
// on seal.
var liveEnvelopes sync.Map // map[*sql.DB]*envelope

// openEnvelope opens realPath as an at-rest-encrypted *sql.DB using the pure-Go
// SQLCipher codec. A new path is seeded; an existing path is decrypted (which
// authenticates page 1, so a wrong key fails closed here). The returned handle
// re-encrypts to realPath on Close.
func openEnvelope(realPath string, key []byte) (*sql.DB, error) {
	if len(key) != 32 {
		return nil, fmt.Errorf("sqlite: envelope key must be 32 bytes, got %d", len(key))
	}
	base, err := ramfsBase()
	if err != nil {
		return nil, err
	}
	tmpDir, err := os.MkdirTemp(base, "hanzo-sqlite-plain-")
	if err != nil {
		return nil, fmt.Errorf("sqlite: envelope scratch dir: %w", err)
	}
	env := &envelope{
		realPath:  realPath,
		tmpDir:    tmpDir,
		plainPath: filepath.Join(tmpDir, "db"),
		key:       append([]byte(nil), key...),
	}

	if fi, statErr := os.Stat(realPath); statErr == nil && fi.Size() > 0 {
		// Existing encrypted database: refuse a hot sidecar, read the salt, decrypt.
		if err := refuseHotSidecar(realPath); err != nil {
			env.shred()
			return nil, err
		}
		salt, err := readSalt(realPath)
		if err != nil {
			env.shred()
			return nil, err
		}
		env.salt = salt
		if err := decryptToPath(env.plainPath, realPath, key); err != nil {
			env.shred()
			return nil, err
		}
	} else {
		// New database: a fresh random salt and the reserve-80 plaintext seed.
		salt := make([]byte, sqlcipher.SaltSize)
		if _, err := rand.Read(salt); err != nil {
			env.shred()
			return nil, fmt.Errorf("sqlite: envelope salt: %w", err)
		}
		env.salt = salt
		seed, err := sqlcipher.EmptyPlaintext(sqlcipher.Params{})
		if err != nil {
			env.shred()
			return nil, err
		}
		if err := os.WriteFile(env.plainPath, seed, 0o600); err != nil {
			env.shred()
			return nil, fmt.Errorf("sqlite: envelope seed: %w", err)
		}
	}

	drv := backendDriver()
	if drv == nil {
		env.shred()
		return nil, fmt.Errorf("sqlite: envelope: no %q driver registered", driverName)
	}
	db := sql.OpenDB(&envelopeConnector{env: env, drv: drv, dsn: plainDSN(env.plainPath)})
	// One plaintext copy, one writer, seal-on-close: cap the pool at a single
	// connection so writes serialize against the file and a checkpoint can quiesce
	// them by holding that one connection.
	db.SetMaxOpenConns(1)
	env.db = db
	liveEnvelopes.Store(db, env)
	return db, nil
}

// envelopeConnector opens plaintext connections to the RAM copy and, when the
// *sql.DB is closed, seals the copy back to the encrypted real path. database/sql
// calls Close on a connector that implements io.Closer when its DB is closed, so
// the seal runs after every pooled connection is closed — exactly once, at the
// right time.
type envelopeConnector struct {
	env *envelope
	drv driver.Driver
	dsn string
}

func (c *envelopeConnector) Connect(ctx context.Context) (driver.Conn, error) {
	return c.drv.Open(c.dsn)
}
func (c *envelopeConnector) Driver() driver.Driver { return c.drv }
func (c *envelopeConnector) Close() error          { return c.env.seal() }

// Checkpoint re-encrypts an open envelope-backed database to its encrypted file
// WITHOUT closing it, so the ciphertext on disk reflects committed writes up to
// this point. It bounds the crash-loss window between the coarse encrypt-on-close
// events. On a database that is not envelope-backed (the live-libsqlcipher or
// unencrypted paths, which persist per-commit) it is a successful no-op.
func Checkpoint(db *sql.DB) error {
	v, ok := liveEnvelopes.Load(db)
	if !ok {
		return nil // not envelope-backed: already durable per-commit
	}
	return v.(*envelope).checkpoint(context.Background())
}

// checkpoint folds any WAL into the plaintext main file and re-encrypts it to the
// real path, holding the single pooled connection for the duration so no
// concurrent write can make the snapshot inconsistent.
func (e *envelope) checkpoint(ctx context.Context) error {
	conn, err := e.db.Conn(ctx)
	if err != nil {
		return fmt.Errorf("sqlite: envelope checkpoint conn %s: %w", e.realPath, err)
	}
	defer conn.Close()
	if _, err := conn.ExecContext(ctx, "PRAGMA wal_checkpoint(TRUNCATE)"); err != nil {
		return fmt.Errorf("sqlite: envelope checkpoint %s: %w", e.realPath, err)
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.sealed {
		return nil
	}
	return encryptToPath(e.realPath, e.plainPath, e.key, e.salt)
}

// seal re-encrypts the plaintext copy to the encrypted real path and shreds the
// copy. It runs once, from Close. A seal failure leaves the last successfully
// sealed ciphertext at realPath and still shreds the plaintext (confidentiality
// over the lost-write: the RAM copy is never left behind).
func (e *envelope) seal() error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.sealed {
		return nil
	}
	e.sealed = true
	liveEnvelopes.Delete(e.db)
	defer e.shredLocked()

	if err := checkpointQuiesce(e.plainPath); err != nil {
		return fmt.Errorf("sqlite: envelope checkpoint %s: %w", e.realPath, err)
	}
	if err := encryptToPath(e.realPath, e.plainPath, e.key, e.salt); err != nil {
		return fmt.Errorf("sqlite: envelope seal %s: %w", e.realPath, err)
	}
	return nil
}

// shred removes the RAM-backed plaintext copy and zeroes the key. Because tmpDir is
// on a memory-backed filesystem, removing it frees the pages; there is no disk
// block to overwrite.
func (e *envelope) shred() {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.shredLocked()
}

func (e *envelope) shredLocked() {
	if e.tmpDir != "" {
		_ = os.RemoveAll(e.tmpDir)
		e.tmpDir = ""
	}
	for i := range e.key {
		e.key[i] = 0
	}
}

// checkpointQuiesce folds any lingering WAL into the plaintext main file so the
// single main file is the complete database before it is encrypted.
//
// SQLite already checkpoints and removes -wal on the last connection close (the
// envelope's pool is closed before seal), so usually nothing remains and this is a
// cheap stat. Only a non-empty -wal (persist_wal, or an unclean state) needs a fresh
// connection to fold it — the common path never pays the reopen.
func checkpointQuiesce(plainPath string) error {
	fi, err := os.Stat(plainPath + "-wal")
	if err != nil || fi.Size() == 0 {
		return nil // no un-folded frames
	}
	db, err := sql.Open("sqlite", plainDSN(plainPath))
	if err != nil {
		return err
	}
	defer db.Close()
	db.SetMaxOpenConns(1)
	_, err = db.Exec("PRAGMA wal_checkpoint(TRUNCATE)")
	return err
}

// plainDSN builds the keyless DSN the envelope opens the plaintext RAM copy with,
// rendered in the active backend's pragma syntax (PragmaDSN). It deliberately does
// NOT use cache=shared: the copy is single-writer (MaxOpenConns 1), and a shared
// in-process page cache would both hold DECRYPTED pages for other connections and
// keep the file locked across the seal reopen (turning the checkpoint into a
// busy_timeout wait).
func plainDSN(plainPath string) string {
	return PragmaDSN(plainPath, DefaultPragmas)
}

// encryptToPath encrypts the plaintext database at plainPath to realPath with the
// SQLCipher codec, under salt, via a temp file + atomic rename so a crash never
// leaves a half-written or plaintext database at realPath. The temp file is in
// realPath's directory (same filesystem → atomic rename) and holds ciphertext, so
// it is safe on persistent storage.
func encryptToPath(realPath, plainPath string, key, salt []byte) error {
	in, err := os.Open(plainPath)
	if err != nil {
		return err
	}
	defer in.Close()

	dir := filepath.Dir(realPath)
	tmp, err := os.CreateTemp(dir, ".enc-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName) // no-op after a successful rename

	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return err
	}
	if err := sqlcipher.EncryptFile(tmp, in, sqlcipher.RawKey(key), salt, sqlcipher.Params{}); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmpName, realPath); err != nil {
		return err
	}
	if d, err := os.Open(dir); err == nil {
		_ = d.Sync()
		_ = d.Close()
	}
	return nil
}

// decryptToPath decrypts the SQLCipher database at realPath to plainPath. DecryptFile
// authenticates page 1 before returning any plaintext, so a wrong key fails here
// (ErrKey) rather than surfacing as corruption later — fail closed.
func decryptToPath(plainPath, realPath string, key []byte) error {
	in, err := os.Open(realPath)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(plainPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	if err := sqlcipher.DecryptFile(out, in, sqlcipher.RawKey(key), sqlcipher.Params{}); err != nil {
		out.Close()
		_ = os.Remove(plainPath)
		return fmt.Errorf("sqlite: decrypt %s (wrong key or corrupt file): %w", realPath, err)
	}
	return out.Close()
}

// readSalt reads the 16-byte SQLCipher salt from the head of an encrypted file.
func readSalt(realPath string) ([]byte, error) {
	f, err := os.Open(realPath)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	head := make([]byte, sqlcipher.SaltSize)
	if _, err := io.ReadFull(f, head); err != nil {
		return nil, fmt.Errorf("sqlite: read salt from %s: %w", realPath, err)
	}
	return sqlcipher.FileSalt(head)
}

// refuseHotSidecar rejects an encrypted database that has a non-empty -wal or
// -journal beside it. Those sidecars carry SQLCipher-encrypted frames whose
// checksums cover ciphertext; the whole-file codec cannot fold them, so a hot
// sidecar means the database was not closed cleanly (or a live C-codec writer holds
// it) and reading it could lose committed data. Our own seal writes only the main
// file, so this only triggers on a foreign writer — fail closed rather than guess.
func refuseHotSidecar(realPath string) error {
	for _, suffix := range []string{"-wal", "-journal"} {
		if fi, err := os.Stat(realPath + suffix); err == nil && fi.Size() > 0 {
			return fmt.Errorf("sqlite: %s has a non-empty %s beside it (unclean close or a live writer); "+
				"the whole-file codec cannot fold an encrypted sidecar — checkpoint and close it cleanly first",
				realPath, suffix)
		}
	}
	return nil
}

// ramfsBase returns a RAM-backed directory to hold the transient plaintext copy, or
// an error if none is available. It NEVER falls back to on-disk storage:
// materialising a decrypted database on a persistent volume is exactly the at-rest
// exposure encryption removes, so a host with no RAM-backed scratch FAILS CLOSED.
//
// Order: the HANZO_SQLITE_RAMFS_DIR override (if RAM-backed), then /dev/shm.
func ramfsBase() (string, error) {
	if d := os.Getenv(ramfsEnv); d != "" {
		if isRAMBacked(d) {
			return d, nil
		}
		return "", fmt.Errorf("sqlite: %s=%q is not RAM-backed (tmpfs/ramfs); refusing to decrypt to persistent storage", ramfsEnv, d)
	}
	const shm = "/dev/shm"
	if isRAMBacked(shm) {
		return shm, nil
	}
	return "", fmt.Errorf("sqlite: no RAM-backed scratch for the pure-Go SQLCipher codec (need tmpfs at /dev/shm or %s); refusing to decrypt to persistent storage", ramfsEnv)
}
