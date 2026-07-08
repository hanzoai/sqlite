package sqlite

import (
	"database/sql"
	"errors"
	"fmt"
	"path/filepath"
	"testing"
)

// TestIsConstraint proves the backend-neutral constraint classifiers match the
// right SQLite extended code under whichever backend this build links — this is
// what lets o11y (and others) drop their direct modernc/mattn error-type checks.
func TestIsConstraint(t *testing.T) {
	db, err := OpenDB(filepath.Join(t.TempDir(), "errcodes.db"), nil)
	if err != nil {
		t.Fatalf("OpenDB: %v", err)
	}
	defer db.Close()

	// UNIQUE and PRIMARY KEY on one table; FK on a child (foreign_keys is ON in
	// the canonical DSN).
	mustExec(t, db, `CREATE TABLE parent (id INTEGER PRIMARY KEY, email TEXT UNIQUE)`)
	mustExec(t, db, `CREATE TABLE child  (id INTEGER PRIMARY KEY, pid INTEGER REFERENCES parent(id))`)
	mustExec(t, db, `INSERT INTO parent (id, email) VALUES (1, 'a@x')`)

	// PRIMARY KEY violation: reuse id 1.
	_, pkErr := db.Exec(`INSERT INTO parent (id, email) VALUES (1, 'b@x')`)
	if pkErr == nil {
		t.Fatal("expected a PRIMARY KEY violation")
	}
	if !IsConstraintPrimaryKey(pkErr) {
		t.Fatalf("IsConstraintPrimaryKey false for %v", pkErr)
	}
	if IsConstraintUnique(pkErr) || IsConstraintForeignKey(pkErr) {
		t.Fatalf("PK error mis-classified as unique/fk: %v", pkErr)
	}

	// UNIQUE violation: reuse email 'a@x' with a fresh id.
	_, uniqErr := db.Exec(`INSERT INTO parent (id, email) VALUES (2, 'a@x')`)
	if uniqErr == nil {
		t.Fatal("expected a UNIQUE violation")
	}
	if !IsConstraintUnique(uniqErr) {
		t.Fatalf("IsConstraintUnique false for %v", uniqErr)
	}
	if IsConstraintPrimaryKey(uniqErr) || IsConstraintForeignKey(uniqErr) {
		t.Fatalf("unique error mis-classified as pk/fk: %v", uniqErr)
	}

	// FOREIGN KEY violation: child points at a non-existent parent.
	_, fkErr := db.Exec(`INSERT INTO child (id, pid) VALUES (1, 999)`)
	if fkErr == nil {
		t.Fatal("expected a FOREIGN KEY violation")
	}
	if !IsConstraintForeignKey(fkErr) {
		t.Fatalf("IsConstraintForeignKey false for %v", fkErr)
	}
	if IsConstraintUnique(fkErr) || IsConstraintPrimaryKey(fkErr) {
		t.Fatalf("fk error mis-classified as unique/pk: %v", fkErr)
	}

	// Non-sqlite and nil errors classify false, never panic.
	plain := errors.New("not a sqlite error")
	if IsConstraintUnique(plain) || IsConstraintPrimaryKey(plain) || IsConstraintForeignKey(plain) {
		t.Fatal("a plain error was classified as a constraint violation")
	}
	if IsConstraintUnique(nil) {
		t.Fatal("nil error classified as a constraint violation")
	}

	// Wrapped sqlite error is still classified (errors.As unwraps).
	wrapped := fmt.Errorf("insert failed: %w", uniqErr)
	if !IsConstraintUnique(wrapped) {
		t.Fatalf("IsConstraintUnique false for wrapped error %v", wrapped)
	}
}

func mustExec(t *testing.T, db *sql.DB, q string) {
	t.Helper()
	if _, err := db.Exec(q); err != nil {
		t.Fatalf("exec %q: %v", q, err)
	}
}
