package sqlite

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"fmt"
	"sync"
)

// driverName is the database/sql driver name registered by BOTH backends
// (driver_nocgo.go registers the pure-Go engine under it; driver_cgo.go
// registers csqlite under it). Tag-neutral single source of truth.
const driverName = "sqlite"

// OpenPragma opens a *sql.DB on the registered "sqlite" backend where EVERY
// pooled connection has the given pragmas applied, in order, via PRAGMA
// statements run at connect time.
//
// Use it for pragmas that must hold on every connection but that the two
// backends do NOT accept uniformly in the DSN. The load-bearing case is
// wal_autocheckpoint: the pure-Go engine honors `?_pragma=wal_autocheckpoint(0)`
// in the DSN, but csqlite silently DROPS it (its DSN grammar has no such param),
// so a binary built CGO=1 would re-enable auto-checkpoint and truncate the WAL
// out from under a WAL-shipping replicator — losing committed frames. Running
// the pragma per connection via ExecContext is backend-neutral (both conns
// implement driver.ExecerContext), so it takes effect either way.
//
// Order matters: put busy_timeout first so a connection blocks on a busy
// database before journal_mode=WAL is attempted (WAL can't be set while another
// connection holds the db).
//
// dsn is a plain (unencrypted) DSN — typically "file:"+path. Encrypted opens go
// through OpenDB (the key binds to the codec VFS, not the DSN). Do NOT also put
// these pragmas in the DSN; they're applied here.
func OpenPragma(dsn string, pragmas []Pragma) (*sql.DB, error) {
	drv := backendDriver()
	if drv == nil {
		return nil, fmt.Errorf("sqlite: OpenPragma: no %q driver registered", driverName)
	}
	return sql.OpenDB(&pragmaConnector{driver: drv, dsn: dsn, pragmas: pragmas}), nil
}

// pragmaConnector is a database/sql Connector that opens a backend connection
// and applies pragmas to it before handing it to the pool. Because the pool
// calls Connect for every new connection, the pragmas hold pool-wide.
type pragmaConnector struct {
	driver  driver.Driver
	dsn     string
	pragmas []Pragma
}

func (pc *pragmaConnector) Connect(ctx context.Context) (driver.Conn, error) {
	conn, err := pc.driver.Open(pc.dsn)
	if err != nil {
		return nil, err
	}
	execer, ok := conn.(driver.ExecerContext)
	if !ok {
		_ = conn.Close()
		return nil, fmt.Errorf("sqlite: OpenPragma: driver conn %T is not a driver.ExecerContext", conn)
	}
	for _, p := range pc.pragmas {
		stmt := "PRAGMA " + p.Name + " = " + p.Value
		if _, err := execer.ExecContext(ctx, stmt, nil); err != nil {
			_ = conn.Close()
			return nil, fmt.Errorf("sqlite: OpenPragma: apply %q: %w", stmt, err)
		}
	}
	return conn, nil
}

func (pc *pragmaConnector) Driver() driver.Driver { return pc.driver }

var (
	backendDriverOnce sync.Once
	backendDriverInst driver.Driver
)

// backendDriver returns the driver.Driver registered under the name "sqlite" by
// this package (csqlite under cgo, the pure-Go engine otherwise). It is resolved
// once, via a throwaway in-memory sql.DB, so the connector stays tag-neutral —
// it needs no per-backend driver symbol and works whichever backend init()
// registered.
func backendDriver() driver.Driver {
	backendDriverOnce.Do(func() {
		db, err := sql.Open(driverName, "file::memory:")
		if err != nil {
			return
		}
		backendDriverInst = db.Driver()
		_ = db.Close()
	})
	return backendDriverInst
}
