//go:build !cgo

package sqlite

import (
	"errors"

	mod "modernc.org/sqlite"
	lib "modernc.org/sqlite/lib"
)

// Reference constraint codes and the error unwrap for the pure-Go/modernc
// backend. The values come from modernc's generated lib package and are the
// same SQLite extended result codes mattn exposes under the CGO build.
var (
	codeConstraintUnique     = lib.SQLITE_CONSTRAINT_UNIQUE
	codeConstraintPrimaryKey = lib.SQLITE_CONSTRAINT_PRIMARYKEY
	codeConstraintForeignKey = lib.SQLITE_CONSTRAINT_FOREIGNKEY
)

// extendedCode extracts SQLite's extended result code from a modernc error.
// *sqlite.Error is a POINTER type with a Code() accessor that returns the
// extended code.
func extendedCode(err error) (int, bool) {
	var e *mod.Error
	if errors.As(err, &e) {
		return e.Code(), true
	}
	return 0, false
}
