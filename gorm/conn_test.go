package sqlite_test

import (
	"path/filepath"
	"testing"

	driver "github.com/hanzoai/sqlite"
	sqlite "github.com/hanzoai/sqlite/gorm"
	"gorm.io/gorm"
)

// TestConnUsesTheCallersPool covers the path where a caller brings their own
// *sql.DB. Upstream carried a DriverName field beside Conn, which did nothing
// once Conn was set — a caller who set both was describing an open that never
// happened. The field is gone here, so that call site fails to compile and its
// author learns the pool is what decides.
func TestConnUsesTheCallersPool(t *testing.T) {
	pool, err := driver.OpenPragma(
		driver.PragmaDSN(filepath.Join(t.TempDir(), "byo.db"), driver.DefaultPragmas),
		driver.DefaultPragmas)
	if err != nil {
		t.Fatalf("open pool: %v", err)
	}
	defer func() { _ = pool.Close() }()

	db, err := gorm.Open(sqlite.New(sqlite.Config{Conn: pool}), &gorm.Config{})
	if err != nil {
		t.Fatalf("gorm.Open with Conn: %v", err)
	}
	if err := db.Exec("CREATE TABLE t (v TEXT)").Error; err != nil {
		t.Fatalf("exec through the caller's pool: %v", err)
	}

	// The pool the caller handed over is the one gorm writes through: a row
	// inserted via gorm is visible on the same *sql.DB without reopening.
	if err := db.Exec("INSERT INTO t VALUES ('x')").Error; err != nil {
		t.Fatalf("insert: %v", err)
	}
	var n int
	if err := pool.QueryRow("SELECT count(*) FROM t").Scan(&n); err != nil {
		t.Fatalf("read back on the caller's pool: %v", err)
	}
	if n != 1 {
		t.Fatalf("caller's pool sees %d rows, want 1 — gorm opened something else", n)
	}
}
