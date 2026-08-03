//go:build cgo && !sqlite_purego

package sqlite

import (
	"context"
	"database/sql"
	"path/filepath"
	"strings"
	"testing"
)

// A keyed store is single-writer, and single-writer has to mean something across
// PROCESSES, not only inside one.
//
// MaxOpenConns(1) and a process-wide write mutex both end at the process
// boundary. Two processes hold the same file during any rolling upgrade of a
// PVC-backed service, and under a deferred BEGIN the second one's
// read-modify-write is refused with SQLITE_BUSY_SNAPSHOT rather than committed
// from its stale read — a dropped write reported as an error, which a caller
// that treats transaction errors as transient will swallow.
//
// These two tests hold the halves of that: that the DSN SAYS immediate, and that
// the driver ACTS on it. Neither is sufficient alone — a parameter this backend
// silently ignored would pass the first and fail the second, which is exactly
// how the pragma set was wrong before it.

func TestDSNBeginsImmediate(t *testing.T) {
	key := make([]byte, 32)
	for _, dsn := range []string{
		DSN("/var/lib/x/store.db", key), // keyed: the cek path
		DSN("/var/lib/x/store.db", nil), // unkeyed: the dev/global engine
	} {
		if !strings.Contains(dsn, "_txlock=immediate") {
			t.Errorf("DSN lacks _txlock=immediate: %s", redactKey(dsn))
		}
	}
}

func TestDriverHonoursImmediate(t *testing.T) {
	path := filepath.Join(t.TempDir(), "tx.db")

	first, err := sql.Open("sqlite", DSN(path, nil))
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	if _, err := first.Exec(`CREATE TABLE t (v INTEGER)`); err != nil {
		t.Fatal(err)
	}

	held, err := first.BeginTx(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer held.Rollback()

	// A second pool on the same file, standing in for a second process. Its
	// BEGIN must block on the RESERVED lock the held transaction already owns
	// and time out at busy_timeout; under a deferred BEGIN it would succeed and
	// go on to read a snapshot it cannot safely write from.
	second, err := sql.Open("sqlite", strings.Replace(DSN(path, nil), "_busy_timeout=10000", "_busy_timeout=200", 1))
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()

	tx, err := second.BeginTx(context.Background(), nil)
	if err == nil {
		tx.Rollback()
		t.Fatal("a second BEGIN succeeded while one was open — _txlock=immediate was accepted and ignored")
	}
}

// redactKey keeps a failure message from printing the raw key the DSN carries.
func redactKey(dsn string) string {
	i := strings.Index(dsn, "key=x'")
	if i < 0 {
		return dsn
	}
	return dsn[:i] + "key=x'…'"
}
