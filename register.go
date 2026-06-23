//go:build cgo

package sqlite

import (
	"database/sql"

	sqlite3 "github.com/mattn/go-sqlite3"
)

// init registers the "sqlite" database/sql driver name — the name
// modernc.org/sqlite registers — backed by go-sqlite3 (CGO) + SQLCipher.
//
// This makes the module a TRUE drop-in via:
//
//	replace modernc.org/sqlite => github.com/hanzoai/sqlite vX.Y.Z
//
// Any code doing `_ "modernc.org/sqlite"` + sql.Open("sqlite", dsn) — e.g.
// Hanzo IAM's xorm engine — then runs on our encrypted CGO engine instead of
// the pure-Go modernc one, which panics at open ("out of memory (14)") in
// some clusters. The SQLCipher key is supplied per-DSN (`?_key=…` / PRAGMA key),
// which is exactly how per-org and per-user DEKs are threaded through.
//
// go-sqlite3 already registers "sqlite3" on its own init, so both names work.
// Requires building with CGO_ENABLED=1 and the `sqlcipher` build tag.
func init() {
	sql.Register("sqlite", &sqlite3.SQLiteDriver{})
}
