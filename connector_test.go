package sqlite

import (
	"context"
	"database/sql"
	"os"
	"path/filepath"
	"testing"
)

// TestOpenPragmaAppliesPerConnection is the load-bearing guarantee: pragmas
// passed to OpenPragma take effect on EVERY pooled connection under whichever
// backend this build links — including wal_autocheckpoint, which mattn drops
// from the DSN. Proven by forcing three distinct live connections and reading
// each one's pragma state.
func TestOpenPragmaAppliesPerConnection(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "pragma.db")

	db, err := OpenPragma("file:"+path, []Pragma{
		{Name: "busy_timeout", Value: "5000"},
		{Name: "journal_mode", Value: "WAL"},
		{Name: "wal_autocheckpoint", Value: "0"},
		{Name: "foreign_keys", Value: "1"},
	})
	if err != nil {
		t.Fatalf("OpenPragma: %v", err)
	}
	defer db.Close()

	// Pin three connections open simultaneously so the pool must mint three
	// distinct backend conns; each must carry the pragmas.
	db.SetMaxOpenConns(3)
	conns := make([]*sql.Conn, 3)
	for i := range conns {
		c, err := db.Conn(ctx)
		if err != nil {
			t.Fatalf("Conn %d: %v", i, err)
		}
		conns[i] = c
		defer c.Close()
	}

	for i, c := range conns {
		var busyTimeout, walAutockpt, foreignKeys int
		var journalMode string
		if err := c.QueryRowContext(ctx, "PRAGMA busy_timeout").Scan(&busyTimeout); err != nil {
			t.Fatalf("conn %d busy_timeout: %v", i, err)
		}
		if err := c.QueryRowContext(ctx, "PRAGMA journal_mode").Scan(&journalMode); err != nil {
			t.Fatalf("conn %d journal_mode: %v", i, err)
		}
		if err := c.QueryRowContext(ctx, "PRAGMA wal_autocheckpoint").Scan(&walAutockpt); err != nil {
			t.Fatalf("conn %d wal_autocheckpoint: %v", i, err)
		}
		if err := c.QueryRowContext(ctx, "PRAGMA foreign_keys").Scan(&foreignKeys); err != nil {
			t.Fatalf("conn %d foreign_keys: %v", i, err)
		}
		if busyTimeout != 5000 {
			t.Errorf("conn %d busy_timeout = %d, want 5000", i, busyTimeout)
		}
		if journalMode != "wal" {
			t.Errorf("conn %d journal_mode = %q, want wal", i, journalMode)
		}
		if walAutockpt != 0 {
			t.Errorf("conn %d wal_autocheckpoint = %d, want 0 (mattn drops this from the DSN — the whole point)", i, walAutockpt)
		}
		if foreignKeys != 1 {
			t.Errorf("conn %d foreign_keys = %d, want 1", i, foreignKeys)
		}
	}
}

// TestSetPersistWAL proves the file control keeps the -wal file across close on
// whichever backend this build links (SQLite otherwise deletes -wal on the last
// clean close), and that a wrong conn type errors instead of panicking.
func TestSetPersistWAL(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "persist.db")

	db, err := OpenDB(path, nil) // OpenDB's DSN sets journal_mode=WAL
	if err != nil {
		t.Fatalf("OpenDB: %v", err)
	}

	conn, err := db.Conn(ctx)
	if err != nil {
		t.Fatalf("Conn: %v", err)
	}
	if err := conn.Raw(func(dc any) error { return SetPersistWAL(dc, true) }); err != nil {
		t.Fatalf("SetPersistWAL: %v", err)
	}
	// Write on the SAME connection so the -wal file is created under persist_wal.
	if _, err := conn.ExecContext(ctx, `CREATE TABLE t (x INTEGER)`); err != nil {
		t.Fatalf("create: %v", err)
	}
	if _, err := conn.ExecContext(ctx, `INSERT INTO t VALUES (1)`); err != nil {
		t.Fatalf("insert: %v", err)
	}
	conn.Close()
	if err := db.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	if _, err := os.Stat(path + "-wal"); err != nil {
		t.Fatalf("-wal file was not kept across close (PERSIST_WAL not honored): %v", err)
	}
}

func TestSetPersistWALWrongConn(t *testing.T) {
	if err := SetPersistWAL(struct{}{}, true); err == nil {
		t.Fatal("expected an error for a non-sqlite driver conn")
	}
}
