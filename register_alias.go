package sqlite

import (
	"database/sql"
	"slices"
)

// legacyName is the driver name this package's cgo backend has always carried
// for drop-in compatibility with the bindings it forks. It resolves on the
// pure-Go build too, because a caller should not have to know which backend was
// linked in order to open a database.
const legacyName = "sqlite3"

// init makes both names resolve on both builds.
//
// The cgo backend already answers to both: this package registers "sqlite" and
// hanzoai/csqlite registers "sqlite3" from its own init. The pure-Go backend
// registered only "sqlite", so the same source opened fine under cgo and
// answered `unknown driver "sqlite3"` in a CGO_ENABLED=0 image — a returned
// error, not a panic, so it surfaced wherever the caller happened to check.
//
// The alias is the SAME driver, looked up rather than constructed, so the two
// names cannot drift into two engines. It registers only when absent, because
// registering a name twice panics before main.
//
// This file sorts after driver_cgo.go and driver_nocgo.go, and Go runs a
// package's init functions in filename order, so the backend has registered
// before this reads it.
func init() {
	if slices.Contains(sql.Drivers(), legacyName) {
		return
	}
	db, err := sql.Open(driverName, "")
	if err != nil {
		return
	}
	d := db.Driver()
	_ = db.Close()
	if d != nil {
		sql.Register(legacyName, d)
	}
}
