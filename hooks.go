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
//	modernc (!cgo):  RegisterCommitHook(func() int32)
//	mattn   (cgo):   RegisterCommitHook(func() int)
//
// so a consumer cannot type-assert a raw driver connection against one shared
// interface (interface satisfaction needs identical method signatures, and each
// backend's method takes its OWN function type). CommitHookRegisterer bridges
// that: it type-asserts the concrete backend conn under the active build tag
// (hooks_cgo.go / hooks_nocgo.go) and returns an adapter speaking the single
// CommitHookFn shape below. Consumers import ONLY this package.

// CommitHookFn is a commit-hook callback. Returning a non-zero value ABORTS the
// commit (SQLite rolls back and reports SQLITE_BUSY); returning zero lets it
// proceed. This is the one callback type consumers use regardless of backend —
// the build-tagged adapter converts it to the backend's native signature.
type CommitHookFn func() int32

// HookRegisterer installs a commit hook on a driver connection. Values
// satisfying it are produced by CommitHookRegisterer, never by asserting a raw
// backend conn directly (see the note above). Passing a nil CommitHookFn clears
// any installed hook.
type HookRegisterer interface {
	RegisterCommitHook(CommitHookFn)
}
