// Plaintext → enveloped-encrypted at-rest migration for a single SQLite file.
//
// This is the generic, schema-agnostic form of the migration Hanzo IAM
// (cmd/sqlite2enveloped) and Hanzo Commerce (db/migrate.go) already run in
// production — lifted into the envelope's own package so every consumer shares
// ONE proven implementation (DRY). It converts a pre-existing PLAINTEXT db into
// the enveloped layout the runtime opens (a SQLCipher-encrypted file + a wrapped
// -DEK `.dek` sidecar), WITHOUT losing a row:
//
//	read plaintext (WAL folded) → replay schema into a fresh encrypted file →
//	copy every row NULL-preserving → verify per-table row-hash parity →
//	atomically swap the encrypted pair in (plaintext kept as `<db>.plaintext.bak`).
//
// It is idempotent: a file that already has a `.dek` sidecar is skipped, so it is
// safe to run repeatedly (self-healing on open, or as a one-shot pass). The
// destination is created via the SAME OpenDB path the runtime opens with, so a
// file this produces is guaranteed reopen-able under UnwrapDEK(DeriveKey(...)).
package sqlite

import (
	"crypto/sha256"
	"database/sql"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"math"
	"os"
	"sort"
	"strings"
)

// dekSuffix names the wrapped-DEK sidecar written beside an encrypted db. It
// matches the convention used by every enveloped consumer (IAM, commerce).
const dekSuffix = ".dek"

// plaintextBakSuffix names the retained plaintext backup after a cutover. It is
// NOT deleted by the migration — a human retires it after confirming the
// encrypted file reads (zero-data-loss net).
const plaintextBakSuffix = ".plaintext.bak"

// MigrateFileToEncrypted converts a single plaintext SQLite file at path into an
// enveloped-encrypted file (SQLCipher pages under a fresh per-file DEK, the DEK
// wrapped AES-256-GCM under KEK=DeriveKey(masterKey, pt, id) into `<path>.dek`).
//
// Returns (rowsCopied, changed, err):
//   - changed=false, err=nil  → no-op: already has a `.dek` sidecar, or the file
//     is absent/empty (a genuinely fresh db is created encrypted on Open, not here).
//   - changed=true,  err=nil  → migrated; `<path>` is now ciphertext, `<path>.dek`
//     holds the wrapped DEK, `<path>.plaintext.bak` holds the original.
//   - err!=nil                → the source is UNTOUCHED (all writes go to a temp
//     file; the atomic cutover is the last step), so the caller can retry.
//
// It FAILS CLOSED on a build that cannot encrypt (pure-Go, or cgo without the
// SQLCipher codec linked) rather than produce a file that only looks migrated.
func MigrateFileToEncrypted(path string, masterKey []byte, pt PrincipalType, id string) (rowsCopied int, changed bool, err error) {
	if len(masterKey) != 32 {
		return 0, false, fmt.Errorf("sqlite/migrate: master key must be 32 bytes, got %d", len(masterKey))
	}
	if !EncryptionAvailable() {
		return 0, false, fmt.Errorf("sqlite/migrate: this build cannot encrypt (pure-Go sqlite); rebuild CGO_ENABLED=1 -tags \"libsqlite3 sqlite_fts5\" linked against libsqlcipher: %w", ErrEncryptionUnavailable)
	}
	if !CodecLinked() {
		return 0, false, fmt.Errorf("sqlite/migrate: cgo build but libsqlcipher is NOT linked (CodecLinked()=false) — the destination would be plaintext; rebuild with -tags \"libsqlite3 sqlite_fts5\" + CGO_LDFLAGS=-lsqlcipher")
	}

	dekPath := path + dekSuffix
	if fileExists(dekPath) {
		return 0, false, nil // already enveloped
	}
	if !fileExists(path) {
		return 0, false, nil // nothing to migrate
	}
	// A file that is already ciphertext but has NO sidecar cannot be recovered by
	// this tool (the DEK is gone) — refuse rather than clobber it as if plaintext.
	plain, err := isPlaintextSQLiteFile(path)
	if err != nil {
		return 0, false, fmt.Errorf("sqlite/migrate: inspect %q: %w", path, err)
	}
	if !plain {
		return 0, false, fmt.Errorf("sqlite/migrate: %q is not plaintext SQLite and has no %s sidecar — refusing (its DEK is unrecoverable)", path, dekSuffix)
	}

	// 1. Open the plaintext source READ-WRITE (never mode=ro) so SQLite runs WAL
	// recovery and every committed frame in a pending -wal becomes visible, then
	// fold the WAL into the main file with a VERIFIED TRUNCATE checkpoint. A busy
	// checkpoint means another connection holds the db — surfaced as an error so a
	// live writer can never let us miss in-flight rows. Only SELECTs are issued
	// afterwards, so the source's logical data is unchanged (retained as .plaintext.bak).
	srcDSN := PragmaDSN(path, []Pragma{
		{Name: "busy_timeout", Value: "10000"},
		{Name: "journal_mode", Value: "WAL"},
	})
	src, err := sql.Open("sqlite", srcDSN)
	if err != nil {
		return 0, false, fmt.Errorf("sqlite/migrate: open plaintext source: %w", err)
	}
	src.SetMaxOpenConns(1)
	defer src.Close()
	if err := src.Ping(); err != nil {
		return 0, false, fmt.Errorf("sqlite/migrate: ping plaintext source: %w", err)
	}
	if err := checkpointWAL(src); err != nil {
		return 0, false, fmt.Errorf("sqlite/migrate: fold source WAL into %q (is the writer stopped?): %w", path, err)
	}

	// 2. Create a fresh encrypted destination at a temp path via the SAME OpenDB
	// path the runtime opens with, so it is guaranteed reopen-able. Mint a DEK,
	// wrap it under the principal KEK, write the temp sidecar.
	tmpDB := path + ".encrypting"
	_ = os.Remove(tmpDB)
	_ = os.Remove(tmpDB + dekSuffix)
	dek, err := NewDEK()
	if err != nil {
		return 0, false, fmt.Errorf("sqlite/migrate: mint DEK: %w", err)
	}
	defer zeroBytes(dek)
	kek, err := DeriveKey(masterKey, pt, id)
	if err != nil {
		return 0, false, fmt.Errorf("sqlite/migrate: derive KEK: %w", err)
	}
	defer zeroBytes(kek)
	blob, err := WrapDEK(kek, dek, PrincipalAAD(pt, id))
	if err != nil {
		return 0, false, fmt.Errorf("sqlite/migrate: wrap DEK: %w", err)
	}
	if err := writeFileAtomic(tmpDB+dekSuffix, blob, 0o600); err != nil {
		return 0, false, fmt.Errorf("sqlite/migrate: write temp sidecar: %w", err)
	}
	dst, err := OpenDB(tmpDB, dek)
	if err != nil {
		return 0, false, fmt.Errorf("sqlite/migrate: open encrypted destination: %w", err)
	}
	dst.SetMaxOpenConns(1) // serialize writes + the pre-cutover checkpoint
	// Foreign keys OFF during bulk copy so table order can't trip a constraint;
	// the source's logical integrity is unchanged and re-checked by parity.
	if _, err := dst.Exec("PRAGMA foreign_keys=OFF"); err != nil {
		dst.Close()
		return 0, false, fmt.Errorf("sqlite/migrate: disable FKs on destination: %w", err)
	}

	// 3. Replay the source schema (tables then indexes; skip auto-indexes whose
	// sql is NULL) and carry the user_version.
	if err := replaySchema(src, dst); err != nil {
		dst.Close()
		return 0, false, fmt.Errorf("sqlite/migrate: replay schema: %w", err)
	}
	var userVersion int
	if err := src.QueryRow("PRAGMA user_version").Scan(&userVersion); err == nil && userVersion != 0 {
		if _, err := dst.Exec(fmt.Sprintf("PRAGMA user_version=%d", userVersion)); err != nil {
			dst.Close()
			return 0, false, fmt.Errorf("sqlite/migrate: set user_version: %w", err)
		}
	}

	// 4. Copy every concrete user table, NULL-preserving.
	tables, err := userTables(src)
	if err != nil {
		dst.Close()
		return 0, false, err
	}
	for _, tbl := range tables {
		n, err := copyTable(src, dst, tbl)
		if err != nil {
			dst.Close()
			return 0, false, fmt.Errorf("sqlite/migrate: copy table %q: %w", tbl, err)
		}
		rowsCopied += n
	}

	// 5. Verify per-table content parity (multiset of row hashes) BEFORE cutover.
	// A dropped/added row or a NULL coerced to "" is caught here — a bare COUNT(*)
	// cannot. On any mismatch the source is left untouched.
	for _, tbl := range tables {
		if err := verifyTableParity(src, dst, tbl); err != nil {
			dst.Close()
			return 0, false, fmt.Errorf("sqlite/migrate: parity check failed for %q — aborting, source untouched: %w", tbl, err)
		}
	}

	// 6. Fold the destination's own WAL into its main file with a verified
	// TRUNCATE checkpoint BEFORE closing, so the encrypted db is a single
	// self-contained file the cutover can rename without orphaning frames.
	if err := checkpointWAL(dst); err != nil {
		dst.Close()
		return 0, false, fmt.Errorf("sqlite/migrate: flush destination WAL: %w", err)
	}
	if err := dst.Close(); err != nil {
		return 0, false, fmt.Errorf("sqlite/migrate: close destination: %w", err)
	}
	_ = src.Close()
	if err := assertNoPendingWAL(tmpDB); err != nil {
		return 0, false, err
	}

	// 7. Atomic cutover: move plaintext aside, swap the encrypted pair into place.
	if err := cutoverEncrypted(path, tmpDB); err != nil {
		return 0, false, err
	}
	return rowsCopied, true, nil
}

// cutoverEncrypted moves the plaintext db to a `.plaintext.bak` backup and
// renames the encrypted temp db (+ sidecar) into the canonical path. The sidecar
// is renamed LAST: until it lands the runtime still refuses the (now-encrypted)
// file, so a crash mid-cutover fails closed rather than exposing a keyless db.
func cutoverEncrypted(dbPath, tmpDB string) error {
	// Stale WAL/SHM companions of the plaintext db must not shadow the new file.
	for _, suf := range []string{"-wal", "-shm"} {
		_ = os.Remove(dbPath + suf)
	}
	if err := os.Rename(dbPath, dbPath+plaintextBakSuffix); err != nil {
		return fmt.Errorf("sqlite/migrate: backup plaintext %q: %w", dbPath, err)
	}
	if err := os.Rename(tmpDB, dbPath); err != nil {
		// Best-effort restore so we never leave the canonical path missing.
		_ = os.Rename(dbPath+plaintextBakSuffix, dbPath)
		return fmt.Errorf("sqlite/migrate: swap encrypted db into %q: %w", dbPath, err)
	}
	for _, suf := range []string{"-wal", "-shm"} {
		_ = os.Remove(tmpDB + suf)
	}
	if err := os.Rename(tmpDB+dekSuffix, dbPath+dekSuffix); err != nil {
		return fmt.Errorf("sqlite/migrate: swap DEK sidecar into %q: %w", dbPath+dekSuffix, err)
	}
	return nil
}

// replaySchema recreates the source's tables then indexes in the destination.
// Auto-indexes (sqlite_autoindex_*) have a NULL `sql` and are excluded; they are
// recreated implicitly by their table's UNIQUE/PK constraints.
func replaySchema(src, dst *sql.DB) error {
	// Tables first, then indexes — two ordered passes so an index never precedes
	// its table.
	for _, typ := range []string{"table", "index"} {
		rows, err := src.Query(`SELECT sql FROM sqlite_master WHERE type=? AND sql IS NOT NULL AND name NOT LIKE 'sqlite_%' ORDER BY rowid`, typ)
		if err != nil {
			return err
		}
		var ddls []string
		for rows.Next() {
			var ddl string
			if err := rows.Scan(&ddl); err != nil {
				rows.Close()
				return err
			}
			ddls = append(ddls, ddl)
		}
		if err := rows.Err(); err != nil {
			rows.Close()
			return err
		}
		rows.Close()
		for _, ddl := range ddls {
			if _, err := dst.Exec(ddl); err != nil {
				return fmt.Errorf("exec %q: %w", firstLine(ddl), err)
			}
		}
	}
	return nil
}

// checkpointWAL folds the write-ahead log into the main file and truncates the
// -wal to zero. It errors unless the checkpoint FULLY completed (busy==0): a
// partial checkpoint leaves committed frames only in the -wal.
func checkpointWAL(db *sql.DB) error {
	var busy, logFrames, checkpointed int
	if err := db.QueryRow(`PRAGMA wal_checkpoint(TRUNCATE)`).Scan(&busy, &logFrames, &checkpointed); err != nil {
		if err == sql.ErrNoRows {
			return nil // non-WAL journal: nothing to fold
		}
		return fmt.Errorf("wal_checkpoint: %w", err)
	}
	if busy != 0 {
		return fmt.Errorf("wal_checkpoint incomplete (busy=%d, log=%d, checkpointed=%d): another connection holds the WAL", busy, logFrames, checkpointed)
	}
	return nil
}

// assertNoPendingWAL fails if dbPath still has a non-empty -wal after a verified
// TRUNCATE checkpoint + close — a surviving one means committed frames would be
// lost by a main-file-only rename. The source is still intact here, so erroring
// lets the caller retry without data loss.
func assertNoPendingWAL(dbPath string) error {
	fi, err := os.Stat(dbPath + "-wal")
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("sqlite/migrate: stat %s-wal: %w", dbPath, err)
	}
	if fi.Size() > 0 {
		return fmt.Errorf("sqlite/migrate: encrypted %q still has a %d-byte -wal after checkpoint+close; refusing cutover to avoid dropping committed frames", dbPath, fi.Size())
	}
	return nil
}

// userTables lists concrete (non-virtual, non-internal) tables to copy.
func userTables(db *sql.DB) ([]string, error) {
	rows, err := db.Query(`SELECT name, sql FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var name, ddl string
		if err := rows.Scan(&name, &ddl); err != nil {
			return nil, err
		}
		if strings.Contains(strings.ToUpper(ddl), "VIRTUAL TABLE") {
			continue // virtual tables are rebuilt from their backing tables, not row-copied
		}
		out = append(out, name)
	}
	return out, rows.Err()
}

// copyTable copies all rows of tbl from src to dst, preserving SQL NULLs and
// storage classes via a per-column *any scan.
func copyTable(src, dst *sql.DB, tbl string) (int, error) {
	cols, err := tableColumns(src, tbl)
	if err != nil {
		return 0, err
	}
	if len(cols) == 0 {
		return 0, nil
	}
	rows, err := src.Query(`SELECT * FROM "` + tbl + `"`)
	if err != nil {
		return 0, err
	}
	defer rows.Close()

	placeholders := strings.TrimSuffix(strings.Repeat("?,", len(cols)), ",")
	insert := fmt.Sprintf(`INSERT INTO "%s" (%s) VALUES (%s)`, tbl, quoteCols(cols), placeholders)

	tx, err := dst.Begin()
	if err != nil {
		return 0, err
	}
	stmt, err := tx.Prepare(insert)
	if err != nil {
		tx.Rollback()
		return 0, err
	}
	n := 0
	for rows.Next() {
		vals := make([]any, len(cols))
		ptrs := make([]any, len(cols))
		for i := range vals {
			ptrs[i] = &vals[i]
		}
		if err := rows.Scan(ptrs...); err != nil {
			tx.Rollback()
			return 0, err
		}
		if _, err := stmt.Exec(vals...); err != nil {
			tx.Rollback()
			return 0, err
		}
		n++
	}
	if err := rows.Err(); err != nil {
		tx.Rollback()
		return 0, err
	}
	if err := tx.Commit(); err != nil {
		return 0, err
	}
	return n, nil
}

// verifyTableParity asserts src and dst hold the SAME multiset of rows for tbl,
// hashing each row with a NULL-sentinel + storage-class-tagged encoding.
func verifyTableParity(src, dst *sql.DB, tbl string) error {
	sh, err := tableRowHashes(src, tbl)
	if err != nil {
		return err
	}
	dh, err := tableRowHashes(dst, tbl)
	if err != nil {
		return err
	}
	if len(sh) != len(dh) {
		return fmt.Errorf("row count mismatch: src=%d dst=%d", len(sh), len(dh))
	}
	sort.Strings(sh)
	sort.Strings(dh)
	for i := range sh {
		if sh[i] != dh[i] {
			return fmt.Errorf("row content mismatch at sorted index %d", i)
		}
	}
	return nil
}

func tableRowHashes(db *sql.DB, tbl string) ([]string, error) {
	rows, err := db.Query(`SELECT * FROM "` + tbl + `"`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	cols, err := rows.Columns()
	if err != nil {
		return nil, err
	}
	var hashes []string
	for rows.Next() {
		vals := make([]any, len(cols))
		ptrs := make([]any, len(cols))
		for i := range vals {
			ptrs[i] = &vals[i]
		}
		if err := rows.Scan(ptrs...); err != nil {
			return nil, err
		}
		hashes = append(hashes, hashRow(vals))
	}
	return hashes, rows.Err()
}

// hashRow computes a canonical, storage-class-tagged, NULL-honouring hash.
func hashRow(vals []any) string {
	h := sha256.New()
	var lenbuf [8]byte
	for _, v := range vals {
		switch t := v.(type) {
		case nil:
			h.Write([]byte{0})
		case int64:
			h.Write([]byte{1})
			binary.BigEndian.PutUint64(lenbuf[:], uint64(t))
			h.Write(lenbuf[:])
		case float64:
			h.Write([]byte{2})
			binary.BigEndian.PutUint64(lenbuf[:], math.Float64bits(t))
			h.Write(lenbuf[:])
		case string:
			h.Write([]byte{3})
			writeLenPrefixed(h, []byte(t), lenbuf[:])
		case []byte:
			h.Write([]byte{4})
			writeLenPrefixed(h, t, lenbuf[:])
		case bool:
			h.Write([]byte{5})
			if t {
				h.Write([]byte{1})
			} else {
				h.Write([]byte{0})
			}
		default:
			h.Write([]byte{9})
			writeLenPrefixed(h, []byte(fmt.Sprintf("%v", t)), lenbuf[:])
		}
	}
	return hex.EncodeToString(h.Sum(nil))
}

func writeLenPrefixed(h interface{ Write([]byte) (int, error) }, b, scratch []byte) {
	binary.BigEndian.PutUint64(scratch[:8], uint64(len(b)))
	h.Write(scratch[:8])
	h.Write(b)
}

func tableColumns(db *sql.DB, tbl string) ([]string, error) {
	rows, err := db.Query(`SELECT name FROM pragma_table_info("` + tbl + `")`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var cols []string
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			return nil, err
		}
		cols = append(cols, name)
	}
	return cols, rows.Err()
}

func quoteCols(cols []string) string {
	q := make([]string, len(cols))
	for i, c := range cols {
		q[i] = `"` + c + `"`
	}
	return strings.Join(q, ",")
}

func firstLine(s string) string {
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return s[:i]
	}
	return s
}
