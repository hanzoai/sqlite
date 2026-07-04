//go:build !cgo || sqlite_purego

package sqlite

import modernc "modernc.org/sqlite"

// CommitHookRegisterer adapts a raw modernc driver connection (obtained from
// (*sql.Conn).Raw) to HookRegisterer. modernc's *conn satisfies
// modernc.HookRegisterer; its native commit-hook type modernc.CommitHookFn is
// `func() int32` — identical underlying shape to our CommitHookFn — so the
// bridge is a direct type conversion. Returns (nil, false) if driverConn is not
// a modernc connection (wrong driver, or a wrapped conn).
func CommitHookRegisterer(driverConn any) (HookRegisterer, bool) {
	c, ok := driverConn.(modernc.HookRegisterer)
	if !ok {
		return nil, false
	}
	return moderncHook{c}, true
}

type moderncHook struct{ c modernc.HookRegisterer }

func (m moderncHook) RegisterCommitHook(cb CommitHookFn) {
	if cb == nil {
		m.c.RegisterCommitHook(nil)
		return
	}
	m.c.RegisterCommitHook(modernc.CommitHookFn(cb))
}
