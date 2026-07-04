package sqlite

import (
	"context"
	"database/sql"
	"fmt"
	"path/filepath"
	"sync/atomic"
	"testing"
)

// TestCommitHookFires proves the unified commit-hook API installs a working
// hook on the active backend's raw driver connection: the hook fires on every
// committed transaction. Runs under BOTH build tags (modernc !cgo / mattn cgo),
// so it verifies CommitHookRegisterer's backend adapter in each.
func TestCommitHookFires(t *testing.T) {
	ctx := context.Background()
	db, err := sql.Open("sqlite", PragmaDSN(filepath.Join(t.TempDir(), "hook.db"), DefaultPragmas))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer db.Close()

	// Pin one connection so the hook and the writes share the same driver conn.
	conn, err := db.Conn(ctx)
	if err != nil {
		t.Fatalf("conn: %v", err)
	}
	defer conn.Close()

	var fired atomic.Int32
	if err := conn.Raw(func(dc any) error {
		reg, ok := CommitHookRegisterer(dc)
		if !ok {
			return fmt.Errorf("CommitHookRegisterer: %T is not a commit-hook conn", dc)
		}
		reg.RegisterCommitHook(func() int32 { fired.Add(1); return 0 })
		return nil
	}); err != nil {
		t.Fatalf("install hook: %v", err)
	}

	if _, err := conn.ExecContext(ctx, `CREATE TABLE t (x INTEGER)`); err != nil {
		t.Fatalf("create: %v", err)
	}
	if _, err := conn.ExecContext(ctx, `INSERT INTO t VALUES (1)`); err != nil {
		t.Fatalf("insert: %v", err)
	}
	if got := fired.Load(); got < 2 {
		t.Fatalf("commit hook fired %d times, want >= 2 (DDL + insert)", got)
	}
}

// TestCommitHookAbortsAndClears proves a non-zero return aborts the commit
// (fail-secure: a broken WAL capture must not silently drop the write) and that
// a nil callback clears the hook so writes proceed again.
func TestCommitHookAbortsAndClears(t *testing.T) {
	ctx := context.Background()
	db, err := sql.Open("sqlite", PragmaDSN(filepath.Join(t.TempDir(), "abort.db"), DefaultPragmas))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer db.Close()

	conn, err := db.Conn(ctx)
	if err != nil {
		t.Fatalf("conn: %v", err)
	}
	defer conn.Close()

	if _, err := conn.ExecContext(ctx, `CREATE TABLE t (x INTEGER)`); err != nil {
		t.Fatalf("create: %v", err)
	}

	var reg HookRegisterer
	if err := conn.Raw(func(dc any) error {
		r, ok := CommitHookRegisterer(dc)
		if !ok {
			return fmt.Errorf("%T is not a commit-hook conn", dc)
		}
		reg = r
		return nil
	}); err != nil {
		t.Fatalf("resolve registerer: %v", err)
	}

	// Non-zero return -> commit is rolled back -> the write errors.
	reg.RegisterCommitHook(func() int32 { return 1 })
	if _, err := conn.ExecContext(ctx, `INSERT INTO t VALUES (1)`); err == nil {
		t.Fatal("expected insert to fail while commit hook aborts, got nil")
	}

	// Clear the hook -> writes proceed.
	reg.RegisterCommitHook(nil)
	if _, err := conn.ExecContext(ctx, `INSERT INTO t VALUES (2)`); err != nil {
		t.Fatalf("insert after clearing hook: %v", err)
	}
	var n int
	if err := conn.QueryRowContext(ctx, `SELECT COUNT(*) FROM t`).Scan(&n); err != nil {
		t.Fatalf("count: %v", err)
	}
	if n != 1 {
		t.Fatalf("row count = %d, want 1 (aborted insert must not persist)", n)
	}
}

// TestCommitHookRegistererRejectsNonConn proves the adapter fails closed on a
// value that is not a driver connection.
func TestCommitHookRegistererRejectsNonConn(t *testing.T) {
	if _, ok := CommitHookRegisterer(42); ok {
		t.Fatal("CommitHookRegisterer(42) reported ok; want false")
	}
}
