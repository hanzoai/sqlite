//go:build !cgo

package sqlite

import (
	"fmt"

	engine "github.com/hanzoai/sqlite/internal/engine"
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
// Pure-Go backend: the vendored engine's *conn satisfies its exported
// FileControl interface; mode 1 enables, 0 disables (-1 would query).
func SetPersistWAL(rawConn any, on bool) error {
	fc, ok := rawConn.(engine.FileControl)
	if !ok {
		return fmt.Errorf("sqlite: SetPersistWAL: driver conn is %T, want engine.FileControl", rawConn)
	}
	mode := 0
	if on {
		mode = 1
	}
	_, err := fc.FileControlPersistWAL("main", mode)
	return err
}
