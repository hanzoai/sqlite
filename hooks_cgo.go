//go:build cgo

package sqlite

import csqlite "github.com/hanzoai/csqlite"

// CommitHookFn is the commit-hook callback under the CGO backend: a distinct
// func() int32 (csqlite has no matching exported type), adapted to csqlite's
// native func() int by CommitHookRegisterer. Consumers cannot assert the raw
// csqlite conn to HookRegisterer under cgo; they must use CommitHookRegisterer.
type CommitHookFn func() int32

// CommitHookRegisterer adapts a raw csqlite driver connection (obtained from
// (*sql.Conn).Raw) to HookRegisterer. csqlite's *SQLiteConn commit-hook type is
// `func() int` (not int32), so the adapter widens our CommitHookFn's int32
// result to csqlite's int. This is the SAME engine driver_cgo.go registers as
// the "sqlite" driver name. Returns (nil, false) if driverConn is not a csqlite
// connection.
func CommitHookRegisterer(driverConn any) (HookRegisterer, bool) {
	c, ok := driverConn.(*csqlite.SQLiteConn)
	if !ok {
		return nil, false
	}
	return csqliteHook{c}, true
}

type csqliteHook struct{ c *csqlite.SQLiteConn }

func (m csqliteHook) RegisterCommitHook(cb CommitHookFn) {
	if cb == nil {
		m.c.RegisterCommitHook(nil)
		return
	}
	m.c.RegisterCommitHook(func() int { return int(cb()) })
}
