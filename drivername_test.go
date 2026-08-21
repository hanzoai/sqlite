package sqlite_test

import (
	"database/sql"
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

// TestSqlite3IsNotAPortableName records that the legacy name is a cgo-only
// accident, so a caller reaching for it learns here rather than in a pure-Go
// image. It asserts the AGREEMENT between the two facts rather than either one
// alone: whether "sqlite3" resolves is allowed to differ by backend, and a
// caller may rely on it in neither.
func TestSqlite3IsNotAPortableName(t *testing.T) {
	registered := slices.Contains(sql.Drivers(), "sqlite3")

	db, err := sql.Open("sqlite3", ":memory:")
	if err == nil {
		err = db.Ping()
		_ = db.Close()
	}

	switch {
	case registered && err != nil:
		t.Fatalf(`"sqlite3" is registered but does not work: %v`, err)
	case !registered && err == nil:
		t.Fatal(`"sqlite3" is not registered yet opened a database, so sql.Drivers() is not the set that resolves`)
	case !registered:
		t.Logf(`"sqlite3" is absent on this backend, as expected without cgo: %v`, err)
	default:
		t.Log(`"sqlite3" resolves on this backend, which is cgo-only and must not be relied on`)
	}
}
