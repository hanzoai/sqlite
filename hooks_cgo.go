//go:build cgo && !sqlite_purego

package sqlite

import sqlite3 "github.com/hanzoai/csqlite"

// CommitHookRegisterer adapts a raw csqlite driver connection (obtained from
// (*sql.Conn).Raw) to HookRegisterer. csqlite's *SQLiteConn commit-hook type is
// `func() int` (not int32), so the adapter widens our CommitHookFn's int32
// result to csqlite's int. This is the SAME engine driver_cgo.go registers as
// the "sqlite" driver name. Returns (nil, false) if driverConn is not a csqlite
// connection.
func CommitHookRegisterer(driverConn any) (HookRegisterer, bool) {
	c, ok := driverConn.(*sqlite3.SQLiteConn)
	if !ok {
		return nil, false
	}
	return cgoHook{c}, true
}

type cgoHook struct{ c *sqlite3.SQLiteConn }

func (m cgoHook) RegisterCommitHook(cb CommitHookFn) {
	if cb == nil {
		m.c.RegisterCommitHook(nil)
		return
	}
	m.c.RegisterCommitHook(func() int { return int(cb()) })
}
