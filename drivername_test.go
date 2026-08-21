package sqlite_test

import (
	"database/sql"
	"path/filepath"
	"slices"
	"testing"

	_ "github.com/hanzoai/sqlite"
)

// THE DRIVER NAME IS "sqlite", ON EVERY BUILD.
//
// This package registers that name under both backends — csqlite against
// libsqlcipher when cgo is on, modernc.org/sqlite when it is not — so a caller
// that opens "sqlite" gets a working database whichever way the binary was
// built, and that is the whole point of the facade.
//
// "sqlite3" is NOT that name, and the difference is invisible until it is
// expensive. Under cgo, csqlite registers "sqlite3" in its own init for
// drop-in compatibility with the bindings it forks, so `sql.Open("sqlite3")`
// works. Without cgo, modernc registers only "sqlite", so the same call fails
// with `unknown driver "sqlite3"`. A repository that opens the legacy name
// therefore passes every test on a developer's cgo machine and dies at the
// first query in a CGO_ENABLED=0 image.
//
// These two tests state both halves so the contract is a property of the
// package rather than something each caller rediscovers.

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
