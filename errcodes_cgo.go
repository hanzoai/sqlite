//go:build cgo && !sqlite_purego

package sqlite

import (
	"errors"

	sqlite3 "github.com/mattn/go-sqlite3"
)

// Reference constraint codes and the error unwrap for the CGO/mattn backend
// (same build condition as driver_cgo.go / hooks_cgo.go). The values are
// SQLite's own extended result codes (numerically identical to modernc's
// lib.SQLITE_CONSTRAINT_*), sourced here from mattn's typed constants.
var (
	codeConstraintUnique     = int(sqlite3.ErrConstraintUnique)
	codeConstraintPrimaryKey = int(sqlite3.ErrConstraintPrimaryKey)
	codeConstraintForeignKey = int(sqlite3.ErrConstraintForeignKey)
)

// extendedCode extracts SQLite's extended result code from a mattn error.
// sqlite3.Error is a VALUE type, so errors.As targets a value, not a pointer.
func extendedCode(err error) (int, bool) {
	var e sqlite3.Error
	if errors.As(err, &e) {
		return int(e.ExtendedCode), true
	}
	return 0, false
}
