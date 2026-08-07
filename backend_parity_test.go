package sqlite_test

import (
	"database/sql"
	"testing"

	_ "github.com/hanzoai/sqlite"
)

// The two backends must answer the SAME SQL, with NO build tags.
//
// This replaces a compile-time assertion in hanzoai/base that refused to build
// a cgo binary unless the caller passed `-tags sqlite_math_functions`. That
// guard was pointing at something real — the cgo backend used to expose a
// SMALLER SQL surface than the pure-Go one, so `acos` existed in production and
// not in a developer's build — but it fixed the asymmetry by making one of the
// two modes fail to compile, which is not two modes agreeing.
//
// csqlite compiles ENABLE_MATH_FUNCTIONS and ENABLE_FTS5 unconditionally now, so
// the asymmetry is gone at its source. This asserts the property directly rather
// than asserting a tag that stands in for it: run it under CGO_ENABLED=1 and
// CGO_ENABLED=0 and it must pass both times. Nothing here needs a tag, and
// nothing downstream should need one either.
func TestBackendParity(t *testing.T) {
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	// The five hanzoai/base's search layer generates (geoDistance).
	var acos, cos, sin, radians, sqrt float64
	if err := db.QueryRow(`select acos(1), cos(0), sin(0), radians(180), sqrt(4)`).
		Scan(&acos, &cos, &sin, &radians, &sqrt); err != nil {
		t.Fatalf("math functions missing on this backend: %v", err)
	}
	if sqrt != 2 || cos != 1 {
		t.Fatalf("math answered wrong: sqrt(4)=%v cos(0)=%v", sqrt, cos)
	}

	// The sanctioned full-text engine; FTS3 is upstream-mattn legacy the pure-Go
	// side does not have, so parity is defined on FTS5.
	if _, err := db.Exec(`create virtual table fts using fts5(body)`); err != nil {
		t.Fatalf("fts5 missing on this backend: %v", err)
	}
}
