package sqlite

import (
	"database/sql"
	"path/filepath"
	"strings"
	"testing"
)

// TestPragmaDSNApplies proves PragmaDSN encodes the pragma set in the ACTIVE
// backend's DSN syntax such that the pragmas actually take effect — not merely
// that the string is well-formed. This is the regression that guards the
// modernc/mattn DSN-format split: it runs green under BOTH build tags.
func TestPragmaDSNApplies(t *testing.T) {
	db, err := sql.Open("sqlite", PragmaDSN(filepath.Join(t.TempDir(), "p.db"), DefaultPragmas))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer db.Close()
	if err := db.Ping(); err != nil {
		t.Fatalf("ping: %v", err)
	}

	var journal string
	if err := db.QueryRow(`PRAGMA journal_mode`).Scan(&journal); err != nil {
		t.Fatalf("query journal_mode: %v", err)
	}
	if !strings.EqualFold(journal, "wal") {
		t.Fatalf("journal_mode = %q, want wal (PragmaDSN did not apply on this backend)", journal)
	}

	var busy int
	if err := db.QueryRow(`PRAGMA busy_timeout`).Scan(&busy); err != nil {
		t.Fatalf("query busy_timeout: %v", err)
	}
	if busy != 10000 {
		t.Fatalf("busy_timeout = %d, want 10000", busy)
	}

	var fk int
	if err := db.QueryRow(`PRAGMA foreign_keys`).Scan(&fk); err != nil {
		t.Fatalf("query foreign_keys: %v", err)
	}
	if fk != 1 {
		t.Fatalf("foreign_keys = %d, want 1", fk)
	}
}
