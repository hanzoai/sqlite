package sqlite

// Backend-neutral classification of SQLite constraint-violation errors.
//
// SQLite's extended result codes (SQLITE_CONSTRAINT_UNIQUE = 2067, etc.) are
// the engine's own numbers and are IDENTICAL across both backends — mattn's
// Error.ExtendedCode and modernc's Error.Code() both return them. Only the
// concrete error TYPE differs (mattn sqlite3.Error value vs modernc *sqlite.Error
// pointer) and only the source of the reference constants differs. So the three
// public predicates live here ONCE, tag-neutral; the per-backend error unwrap
// (extendedCode) and the constant values (codeConstraint*) are supplied by the
// build-tagged errcodes_cgo.go / errcodes_nocgo.go (same tag scheme as the
// driver and hooks: cgo&&!sqlite_purego → mattn, else modernc).
//
// Consumers replace direct `err.(*modernc.Error).Code() == lib.SQLITE_...`
// checks with these, so no code outside this package imports a sqlite backend
// to classify errors.

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

// IsConstraint reports whether err is a constraint violation of ANY kind —
// UNIQUE, PRIMARY KEY, FOREIGN KEY, CHECK, NOT NULL, TRIGGER and the rest of the
// family.
//
// It is the predicate a caller wants when the remedy is the same whichever
// constraint failed, and the three specific ones above are not a substitute for
// it: each matches exactly one extended code, so classifying a NOT NULL
// violation with IsConstraintUnique answers false and the caller silently stops
// handling a case it used to handle.
//
// The test is SQLite's own: an extended result code carries its primary code in
// the low eight bits (SQLITE_CONSTRAINT_UNIQUE 2067 & 0xff == SQLITE_CONSTRAINT
// 19), so masking classifies the whole family without enumerating it — a
// constraint kind added by a future SQLite is matched by this and by no list.
func IsConstraint(err error) bool {
	c, ok := extendedCode(err)
	return ok && c&0xff == codeConstraint
}
