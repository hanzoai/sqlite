//go:build cgo

package sqlite

import (
	"errors"

	csqlite "github.com/hanzoai/csqlite"
)

// Reference constraint codes and the error unwrap for the CGO/csqlite backend
// (same build condition as driver_cgo.go / hooks_cgo.go). The values are
// SQLite's own extended result codes, sourced here from csqlite's typed
// constants.
var (
	codeConstraintUnique     = int(csqlite.ErrConstraintUnique)
	codeConstraintPrimaryKey = int(csqlite.ErrConstraintPrimaryKey)
	codeConstraintForeignKey = int(csqlite.ErrConstraintForeignKey)
)

// extendedCode extracts SQLite's extended result code from a csqlite error.
// csqlite.Error is a VALUE type, so errors.As targets a value, not a pointer.
func extendedCode(err error) (int, bool) {
	var e csqlite.Error
	if errors.As(err, &e) {
		return int(e.ExtendedCode), true
	}
	return 0, false
}
