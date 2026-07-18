//go:build cgo

package sqlite

import (
	"fmt"

	csqlite "github.com/hanzoai/csqlite"
)

// SetPersistWAL sets SQLite's SQLITE_FCNTL_PERSIST_WAL file control on rawConn —
// the raw driver connection handed to the callback of (*sql.Conn).Raw. When on,
// the -wal file is kept across the last connection close (SQLite otherwise
// deletes it), which WAL-shipping replication (hanzoai/replicate) requires so a
// crash mid-sync doesn't lose committed frames.
//
// It is the one backend-neutral way to set PERSIST_WAL; consumers never touch
// the concrete conn type directly. Returns an error if rawConn is not this
// build's SQLite connection type.
//
// CGO backend: csqlite exposes SetFileControlInt; the op constant is csqlite's
// own SQLITE_FCNTL_PERSIST_WAL (= 10).
func SetPersistWAL(rawConn any, on bool) error {
	c, ok := rawConn.(*csqlite.SQLiteConn)
	if !ok {
		return fmt.Errorf("sqlite: SetPersistWAL: driver conn is %T, want *csqlite.SQLiteConn", rawConn)
	}
	arg := 0
	if on {
		arg = 1
	}
	return c.SetFileControlInt("main", csqlite.SQLITE_FCNTL_PERSIST_WAL, arg)
}
