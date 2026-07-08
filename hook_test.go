package sqlite

import (
	"context"
	"path/filepath"
	"testing"
)

// TestRegisterCommitHook proves the backend-neutral commit hook fires on commit
// (the contract Base's WAL replication depends on) and that a non-zero return
// aborts the commit — under whichever backend this build links.
func TestRegisterCommitHook(t *testing.T) {
	ctx := context.Background()
	db, err := OpenDB(filepath.Join(t.TempDir(), "hook.db"), nil)
	if err != nil {
		t.Fatalf("OpenDB: %v", err)
	}
	defer db.Close()

	// The hook is per-connection, so pin one *sql.Conn and drive all writes on
	// it (autocommit → each statement is its own commit).
	conn, err := db.Conn(ctx)
	if err != nil {
		t.Fatalf("Conn: %v", err)
	}
	defer conn.Close()

	if _, err := conn.ExecContext(ctx, `CREATE TABLE t (x INTEGER)`); err != nil {
		t.Fatalf("create: %v", err)
	}

	var fired int
	allow := true
	if err := conn.Raw(func(dc any) error {
		return RegisterCommitHook(dc, func() int {
			fired++
			if allow {
				return 0
			}
			return 1
		})
	}); err != nil {
		t.Fatalf("RegisterCommitHook: %v", err)
	}

	// Allow path: commit succeeds, hook fires, row persists.
	if _, err := conn.ExecContext(ctx, `INSERT INTO t VALUES (1)`); err != nil {
		t.Fatalf("insert (allow): %v", err)
	}
	if fired == 0 {
		t.Fatal("commit hook did not fire on an allowed commit")
	}

	var n int
	if err := conn.QueryRowContext(ctx, `SELECT count(*) FROM t`).Scan(&n); err != nil {
		t.Fatalf("count after allow: %v", err)
	}
	if n != 1 {
		t.Fatalf("row not persisted on allowed commit: count=%d", n)
	}

	// Abort path: hook returns non-zero → commit becomes a rollback, so the
	// second row must NOT be present (the statement errors on both backends).
	allow = true
	before := fired
	allow = false
	if _, err := conn.ExecContext(ctx, `INSERT INTO t VALUES (2)`); err == nil {
		t.Fatal("expected an error when the commit hook aborts the commit")
	}
	if fired <= before {
		t.Fatal("commit hook did not fire on the aborting commit")
	}
	if err := conn.QueryRowContext(ctx, `SELECT count(*) FROM t`).Scan(&n); err != nil {
		t.Fatalf("count after abort: %v", err)
	}
	if n != 1 {
		t.Fatalf("aborted commit persisted a row: count=%d (want 1)", n)
	}

	// Clearing the hook (nil) must not error and stops further firing.
	if err := conn.Raw(func(dc any) error { return RegisterCommitHook(dc, nil) }); err != nil {
		t.Fatalf("clear hook: %v", err)
	}
	allow = true
	cleared := fired
	if _, err := conn.ExecContext(ctx, `INSERT INTO t VALUES (3)`); err != nil {
		t.Fatalf("insert after clear: %v", err)
	}
	if fired != cleared {
		t.Fatalf("cleared commit hook still fired: %d → %d", cleared, fired)
	}
}

// TestRegisterCommitHookWrongConn ensures a non-sqlite driver conn is rejected
// with a clear error rather than a panic.
func TestRegisterCommitHookWrongConn(t *testing.T) {
	if err := RegisterCommitHook(struct{}{}, func() int { return 0 }); err == nil {
		t.Fatal("expected an error for a non-sqlite driver conn")
	}
}
