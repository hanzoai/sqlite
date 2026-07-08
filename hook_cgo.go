//go:build cgo

package sqlite

import (
	"fmt"

	sqlite3 "github.com/mattn/go-sqlite3"
)

// RegisterCommitHook installs commit as the SQLite commit hook on rawConn — the
// raw driver connection handed to the callback of (*sql.Conn).Raw. It is the
// one backend-neutral way to wire a commit hook; consumers never touch the
// mattn/modernc conn type directly.
//
// commit follows SQLite's sqlite3_commit_hook contract: return zero to allow
// the pending commit, non-zero to convert it into a rollback. A nil commit
// clears any previously-installed hook.
//
// It returns an error if rawConn is not this build's SQLite connection type
// (i.e. Raw was called on a non-sqlite driver).
//
// CGO backend: mattn/go-sqlite3, whose *SQLiteConn.RegisterCommitHook already
// takes func() int, so commit is installed verbatim.
func RegisterCommitHook(rawConn any, commit func() int) error {
	c, ok := rawConn.(*sqlite3.SQLiteConn)
	if !ok {
		return fmt.Errorf("sqlite: RegisterCommitHook: driver conn is %T, want *sqlite3.SQLiteConn", rawConn)
	}
	c.RegisterCommitHook(commit)
	return nil
}
