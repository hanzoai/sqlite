//go:build !cgo

package sqlite

import (
	"errors"

	engine "github.com/hanzoai/sqlite/internal/engine"
	lib "github.com/hanzoai/sqlite/internal/engine/lib"
)

// Reference constraint codes and the error unwrap for the pure-Go engine backend
// (same build condition as driver_nocgo.go / hooks_nocgo.go). The values come
// from the vendored engine's generated lib package and are the SQLite extended
// result codes.
var (
	codeConstraintUnique     = lib.SQLITE_CONSTRAINT_UNIQUE
	codeConstraintPrimaryKey = lib.SQLITE_CONSTRAINT_PRIMARYKEY
	codeConstraintForeignKey = lib.SQLITE_CONSTRAINT_FOREIGNKEY
)

// extendedCode extracts SQLite's extended result code from a pure-Go engine
// error. *engine.Error is a POINTER type with a Code() accessor that returns the
// extended code.
func extendedCode(err error) (int, bool) {
	var e *engine.Error
	if errors.As(err, &e) {
		return e.Code(), true
	}
	return 0, false
}
