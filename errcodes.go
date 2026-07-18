package sqlite

// Backend-neutral classification of SQLite constraint-violation errors.
//
// SQLite's extended result codes (SQLITE_CONSTRAINT_UNIQUE = 2067, etc.) are the
// engine's own numbers and are IDENTICAL across both backends. Only the concrete
// error TYPE differs (csqlite Error value vs the pure-Go engine's *Error pointer)
// and only the source of the reference constants differs. So the three public
// predicates live here ONCE, tag-neutral; the per-backend error unwrap
// (extendedCode) and the constant values (codeConstraint*) are supplied by the
// build-tagged errcodes_cgo.go / errcodes_nocgo.go.
//
// Consumers replace direct backend-specific `Code() == SQLITE_...` checks with
// these, so no code outside this package imports a sqlite backend to classify
// errors.

// IsConstraintUnique reports whether err is a UNIQUE-constraint violation from
// the active SQLite backend. It unwraps via errors.As, so a wrapped error is
// still classified. Returns false for a nil or non-sqlite error.
func IsConstraintUnique(err error) bool {
	c, ok := extendedCode(err)
	return ok && c == codeConstraintUnique
}

// IsConstraintPrimaryKey reports whether err is a PRIMARY KEY-constraint
// violation from the active SQLite backend.
func IsConstraintPrimaryKey(err error) bool {
	c, ok := extendedCode(err)
	return ok && c == codeConstraintPrimaryKey
}

// IsConstraintForeignKey reports whether err is a FOREIGN KEY-constraint
// violation from the active SQLite backend.
func IsConstraintForeignKey(err error) bool {
	c, ok := extendedCode(err)
	return ok && c == codeConstraintForeignKey
}
