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

// TestIsConstraintCatchesTheWholeFamily is why the generic predicate exists: the
// three specific ones each match ONE extended code, so a caller that reaches for
// the nearest of them to classify a NOT NULL or CHECK violation gets false and
// stops handling a case it used to handle.
func TestIsConstraintCatchesTheWholeFamily(t *testing.T) {
	db, err := OpenDB(filepath.Join(t.TempDir(), "family.db"), nil)
	if err != nil {
		t.Fatalf("OpenDB: %v", err)
	}
	defer db.Close()

	mustExec(t, db, `CREATE TABLE t (
		id    INTEGER PRIMARY KEY,
		name  TEXT NOT NULL,
		email TEXT UNIQUE,
		age   INTEGER CHECK (age >= 0)
	)`)
	mustExec(t, db, `INSERT INTO t (id, name, email, age) VALUES (1, 'a', 'a@x', 30)`)

	// Each of these violates a DIFFERENT constraint, and only the first two are
	// classified by any of the specific predicates.
	for _, c := range []struct {
		kind     string
		stmt     string
		specific func(error) bool
	}{
		{"UNIQUE", `INSERT INTO t (id, name, email, age) VALUES (2, 'b', 'a@x', 30)`, IsConstraintUnique},
		{"PRIMARY KEY", `INSERT INTO t (id, name, email, age) VALUES (1, 'c', 'c@x', 30)`, IsConstraintPrimaryKey},
		{"NOT NULL", `INSERT INTO t (id, name, email, age) VALUES (3, NULL, 'd@x', 30)`, nil},
		{"CHECK", `INSERT INTO t (id, name, email, age) VALUES (4, 'e', 'e@x', -1)`, nil},
	} {
		_, err := db.Exec(c.stmt)
		if err == nil {
			t.Fatalf("%s: expected a violation", c.kind)
		}
		if !IsConstraint(err) {
			t.Errorf("%s: IsConstraint false for %v", c.kind, err)
		}
		// The half that makes the generic predicate load-bearing rather than a
		// convenience: for NOT NULL and CHECK, every specific predicate answers
		// false, so substituting one of them loses the case entirely.
		if c.specific == nil {
			if IsConstraintUnique(err) || IsConstraintPrimaryKey(err) || IsConstraintForeignKey(err) {
				t.Errorf("%s: a specific predicate claimed it, so this case no longer proves the gap: %v", c.kind, err)
			}
		} else if !c.specific(err) {
			t.Errorf("%s: its own specific predicate answered false for %v", c.kind, err)
		}
	}

	// A non-sqlite error and nil are not constraint violations.
	if IsConstraint(nil) || IsConstraint(errors.New("plain")) {
		t.Error("IsConstraint claimed a nil or non-sqlite error")
	}
}
