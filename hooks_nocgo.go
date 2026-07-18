//go:build !cgo

package sqlite

import engine "github.com/hanzoai/sqlite/internal/engine"

// CommitHookFn is a type ALIAS for the vendored engine's commit-hook callback
// type. Because it is the SAME type (not merely the same underlying func()
// int32), the engine's *conn — whose RegisterCommitHook takes engine.CommitHookFn
// — satisfies HookRegisterer directly, so consumers (Hanzo Base) can
// `driverConn.(sqlite.HookRegisterer)` on the raw conn with no bridge.
type CommitHookFn = engine.CommitHookFn

// CommitHookRegisterer adapts a raw pure-Go engine driver connection (obtained
// from (*sql.Conn).Raw) to HookRegisterer. The engine's *conn satisfies
// engine.HookRegisterer; its native commit-hook type engine.CommitHookFn is
// `func() int32` — identical underlying shape to our CommitHookFn — so the
// bridge is a direct type conversion. Returns (nil, false) if driverConn is not
// an engine connection (wrong driver, or a wrapped conn).
func CommitHookRegisterer(driverConn any) (HookRegisterer, bool) {
	c, ok := driverConn.(engine.HookRegisterer)
	if !ok {
		return nil, false
	}
	return engineHook{c}, true
}

type engineHook struct{ c engine.HookRegisterer }

// CommitHookFn IS engine.CommitHookFn (alias), so this is a direct call; a nil cb
// clears the hook.
func (m engineHook) RegisterCommitHook(cb CommitHookFn) { m.c.RegisterCommitHook(cb) }
