//go:build !cgo

package sqlite

import engine "github.com/hanzoai/sqlite/internal/engine"

// Connection-hook surface — re-exported from the vendored pure-Go engine so
// external HA/replication libraries (e.g. litesql/go-sqlite-ha, used by base-ha)
// can migrate off modernc.org/sqlite WITHOUT importing internal packages. These
// are the pure-Go engine's connection-hook feature; there is no CGO analogue
// (csqlite has a different hook model), so they exist only under !cgo — the
// backend base-ha and the HA layer run on.

// Driver is the pure-Go SQLite driver type. A zero value is usable: register
// connection hooks on it, then hand &Driver to a database/sql connector. This is
// the same driver type registered under the "sqlite" name; go-sqlite-ha does
// `var drv sqlite.Driver; drv.RegisterConnectionHook(fn)` then opens through it.
type Driver = engine.Driver

// ExecQuerierContext is the exec+query surface a ConnectionHookFn receives: the
// minimal handle a hook uses to run setup SQL on each new connection before it
// enters the pool.
type ExecQuerierContext = engine.ExecQuerierContext

// ConnectionHookFn runs on every new connection the driver opens, after setup
// and before the connection enters the pool — the hook point HA/replication
// layers install their per-connection wiring on.
type ConnectionHookFn = engine.ConnectionHookFn

// RegisterConnectionHook installs fn on the driver registered under the "sqlite"
// name; fn then runs for every new connection opened via sql.Open("sqlite", …).
// (A private Driver instance registers hooks via its own RegisterConnectionHook
// method — see Driver.)
func RegisterConnectionHook(fn ConnectionHookFn) { engine.RegisterConnectionHook(fn) }
