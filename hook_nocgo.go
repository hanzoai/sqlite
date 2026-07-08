//go:build !cgo

package sqlite

import (
	"fmt"

	mod "modernc.org/sqlite"
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
// Pure-Go backend: modernc.org/sqlite exposes the exported HookRegisterer
// interface whose RegisterCommitHook takes CommitHookFn (func() int32); commit
// (func() int) is adapted to it so the caller sees ONE signature under both
// build tags.
func RegisterCommitHook(rawConn any, commit func() int) error {
	c, ok := rawConn.(mod.HookRegisterer)
	if !ok {
		return fmt.Errorf("sqlite: RegisterCommitHook: driver conn is %T, want modernc.HookRegisterer", rawConn)
	}
	if commit == nil {
		c.RegisterCommitHook(nil)
		return nil
	}
	c.RegisterCommitHook(func() int32 { return int32(commit()) })
	return nil
}
