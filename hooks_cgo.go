//go:build cgo && !sqlite_purego

package sqlite

import sqlite3 "github.com/mattn/go-sqlite3"

// CommitHookRegisterer adapts a raw mattn driver connection (obtained from
// (*sql.Conn).Raw) to HookRegisterer. mattn's *SQLiteConn commit-hook type is
// `func() int` (not int32), so the adapter widens our CommitHookFn's int32
// result to mattn's int. This is the SAME engine driver_cgo.go registers as the
// "sqlite" driver name. Returns (nil, false) if driverConn is not a mattn
// connection.
func CommitHookRegisterer(driverConn any) (HookRegisterer, bool) {
	c, ok := driverConn.(*sqlite3.SQLiteConn)
	if !ok {
		return nil, false
	}
	return mattnHook{c}, true
}

type mattnHook struct{ c *sqlite3.SQLiteConn }

func (m mattnHook) RegisterCommitHook(cb CommitHookFn) {
	if cb == nil {
		m.c.RegisterCommitHook(nil)
		return
	}
	m.c.RegisterCommitHook(func() int { return int(cb()) })
}
