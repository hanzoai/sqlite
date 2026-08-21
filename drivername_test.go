package sqlite_test

import (
	"database/sql"
	"path/filepath"
	"slices"
	"testing"

	_ "github.com/hanzoai/sqlite"
)

// BOTH NAMES OPEN THIS DRIVER, ON EVERY BUILD.
//
// "sqlite" is the name to write. It is registered under both backends — csqlite
// against libsqlcipher when cgo is on, a pure-Go engine when it is not — so a
// caller gets a working database whichever way the binary was built, and that is
// the point of the facade.
//
// "sqlite3" is an alias to the SAME driver value, registered here when the
// backend has not already claimed it. It used to resolve only under cgo, where
// csqlite registers it for drop-in compatibility with the bindings it forks;
// identical source then opened on a developer machine and answered
// `unknown driver "sqlite3"` in a CGO_ENABLED=0 image. That is closed, so a
// legacy name is style rather than a defect.
//
// These tests state the contract so it is a property of the package rather than
// something each caller rediscovers: both names resolve, and they are one engine
// — a database written through either reads back through the other.

// TestSqliteIsRegisteredOnEveryBuild is the guarantee the facade exists to make.
func TestSqliteIsRegisteredOnEveryBuild(t *testing.T) {
	if !slices.Contains(sql.Drivers(), "sqlite") {
		t.Fatalf(`the "sqlite" driver is not registered; sql.Drivers() = %v`, sql.Drivers())
	}
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatalf(`sql.Open("sqlite"): %v`, err)
	}
	defer func() { _ = db.Close() }()
	if err := db.Ping(); err != nil {
		t.Fatalf("ping: %v", err)
	}
	var answer int
	if err := db.QueryRow("SELECT 1").Scan(&answer); err != nil {
		t.Fatalf("query: %v", err)
	}
	if answer != 1 {
		t.Fatalf("SELECT 1 returned %d", answer)
	}
}

// TestBothNamesOpenTheSameEngine is the compatibility half: "sqlite3" resolves
// on EVERY build too, and it is the same driver rather than a second engine.
//
// It used to resolve only under cgo, where hanzoai/csqlite registers it for
// drop-in compatibility with the bindings it forks. The pure-Go build answered
// `unknown driver "sqlite3"`, so identical source opened on a developer's
// machine and failed in a CGO_ENABLED=0 image.
func TestBothNamesOpenTheSameEngine(t *testing.T) {
	for _, name := range []string{"sqlite", "sqlite3"} {
		if !slices.Contains(sql.Drivers(), name) {
			t.Fatalf("%q is not registered; sql.Drivers() = %v", name, sql.Drivers())
		}
		db, err := sql.Open(name, ":memory:")
		if err != nil {
			t.Fatalf("sql.Open(%q): %v", name, err)
		}
		var answer int
		if err := db.QueryRow("SELECT 1").Scan(&answer); err != nil {
			t.Fatalf("query through %q: %v", name, err)
		}
		if answer != 1 {
			t.Fatalf("SELECT 1 through %q returned %d", name, answer)
		}
		_ = db.Close()
	}
}

// TestTheAliasIsNotASecondEngine pins what makes the alias safe: it is the same
// driver value, so a database written through one name is readable through the
// other and no second implementation can drift in behind it.
func TestTheAliasIsNotASecondEngine(t *testing.T) {
	path := filepath.Join(t.TempDir(), "shared.db")

	w, err := sql.Open("sqlite", "file:"+path)
	if err != nil {
		t.Fatalf("open for write: %v", err)
	}
	if _, err := w.Exec("CREATE TABLE t (v TEXT); INSERT INTO t VALUES ('x')"); err != nil {
		t.Fatalf("write: %v", err)
	}
	_ = w.Close()

	r, err := sql.Open("sqlite3", "file:"+path)
	if err != nil {
		t.Fatalf("open for read: %v", err)
	}
	defer func() { _ = r.Close() }()
	var v string
	if err := r.QueryRow("SELECT v FROM t").Scan(&v); err != nil {
		t.Fatalf("read back through the alias: %v", err)
	}
	if v != "x" {
		t.Fatalf("read %q, want %q", v, "x")
	}
}
