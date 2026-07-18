package sqlite

// Commit-hook surface — one API, two backends (selected by build tag).
//
// A SQLite commit hook fires inside the engine at COMMIT time; returning a
// non-zero value aborts the transaction (SQLite rolls it back and surfaces
// SQLITE_BUSY). Hanzo Base uses it to capture per-transaction WAL frames for
// cross-pod replication + point-in-time recovery.
//
// The two backends expose DIFFERENT native callback signatures:
//
//	pure-Go (!cgo):  RegisterCommitHook(func() int32)
//	cgo/csqlite:     RegisterCommitHook(func() int)
//
// so a consumer cannot type-assert a raw driver connection against one shared
// interface (interface satisfaction needs identical method signatures, and each
// backend's method takes its OWN function type). CommitHookRegisterer bridges
// that: it type-asserts the concrete backend conn under the active build tag
// (hooks_cgo.go / hooks_nocgo.go) and returns an adapter speaking the single
// CommitHookFn shape below. Consumers import ONLY this package.

// CommitHookFn is a commit-hook callback (func() int32). Returning a non-zero
// value ABORTS the commit (SQLite rolls back and reports SQLITE_BUSY); returning
// zero lets it proceed. It is defined per backend (hooks_cgo.go / hooks_nocgo.go):
// under !cgo it is a type ALIAS for the vendored engine's CommitHookFn, so the
// raw engine connection satisfies HookRegisterer directly (a consumer can
// `driverConn.(sqlite.HookRegisterer)` with no bridge); under cgo it is a
// distinct func() int32 that the CommitHookRegisterer bridge adapts to csqlite's
// func() int callback.

// HookRegisterer installs a commit hook on a driver connection. Passing a nil
// CommitHookFn clears any installed hook. Under !cgo the raw engine conn
// satisfies this directly; under cgo, obtain one via CommitHookRegisterer.
type HookRegisterer interface {
	RegisterCommitHook(CommitHookFn)
}
