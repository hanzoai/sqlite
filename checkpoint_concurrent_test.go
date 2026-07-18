package sqlite

import (
	"database/sql"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// TestConcurrentCheckpointUnderLoad is the verification bar for concurrent-
// checkpoint locking — the property WAL-shipping replication (hanzoai/replicate)
// depends on. It runs a TRUNCATE-checkpoint loop on one connection while several
// writers hammer INSERTs on another, then asserts:
//
//   - no wal_checkpoint(TRUNCATE) ever fails with a hard SQLITE_BUSY statement
//     error (busy_timeout must make the checkpoint BLOCK for the writer lock, not
//     bail — this is exactly what a broken/regressed blocking-lock path breaks);
//   - the checkpoint actually completes (busy=0) at least once under load;
//   - every committed row survives (TRUNCATE never truncates un-checkpointed
//     frames out from under a writer — no data loss);
//   - reopening the file reads every row back (durable, uncorrupted).
//
// It is backend-neutral: OpenPragma applies busy_timeout + wal_autocheckpoint=0
// on every pooled connection under both the pure-Go and CGO backends, so the
// same bar guards both. busy_timeout is generous (10s) because the correctness
// claim is "the checkpoint blocks and then succeeds", not "it succeeds within an
// arbitrarily tight deadline".
func TestConcurrentCheckpointUnderLoad(t *testing.T) {
	const (
		writers      = 4
		perWriter    = 150
		checkpoints  = 40
		blobSize     = 4000
		busyTimeout  = "10000"
		checkpointBT = "10000"
	)
	dir := t.TempDir()
	path := filepath.Join(dir, "ckpt.db")

	// Writers pool: busy_timeout so a writer BLOCKS on the checkpoint's lock
	// instead of erroring; WAL so the checkpoint has something to reclaim.
	w, err := OpenPragma("file:"+path, []Pragma{
		{Name: "busy_timeout", Value: busyTimeout},
		{Name: "journal_mode", Value: "WAL"},
		{Name: "synchronous", Value: "NORMAL"},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()
	w.SetMaxOpenConns(writers)
	if _, err := w.Exec(`CREATE TABLE t (id INTEGER PRIMARY KEY, v BLOB)`); err != nil {
		t.Fatal(err)
	}

	// Checkpointer: single connection, busy_timeout, auto-checkpoint OFF so the
	// only checkpoints are the explicit TRUNCATEs below (mirrors replicate).
	c, err := OpenPragma("file:"+path, []Pragma{
		{Name: "busy_timeout", Value: checkpointBT},
		{Name: "wal_autocheckpoint", Value: "0"},
		{Name: "journal_mode", Value: "WAL"},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.SetMaxOpenConns(1)

	// Fire the writers.
	var wrote int64
	var firstWrite sync.Once
	started := make(chan struct{})
	var wg sync.WaitGroup
	blob := make([]byte, blobSize)
	for g := 0; g < writers; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < perWriter; i++ {
				for {
					_, err := w.Exec(`INSERT INTO t (v) VALUES (?)`, blob)
					if err == nil {
						break
					}
					if isBusy(err) { // a well-behaved writer retries; must never see this with busy_timeout, but be safe
						time.Sleep(time.Millisecond)
						continue
					}
					t.Errorf("writer insert: %v", err)
					return
				}
				atomic.AddInt64(&wrote, 1)
				firstWrite.Do(func() { close(started) })
			}
		}()
	}
	<-started // don't checkpoint an empty WAL

	// Hammer TRUNCATE checkpoints concurrently with the writers.
	var completed, incomplete int
	for k := 0; k < checkpoints; k++ {
		var busy, logN, ckN int
		if err := c.QueryRow(`PRAGMA wal_checkpoint(TRUNCATE)`).Scan(&busy, &logN, &ckN); err != nil {
			// The regression signature: TRUNCATE returns SQLITE_BUSY as a hard
			// statement error instead of blocking on busy_timeout.
			t.Fatalf("checkpoint %d hard-failed (blocking-lock regression): %v", k, err)
		}
		if busy == 0 {
			completed++
		} else {
			incomplete++
		}
		time.Sleep(time.Millisecond)
	}
	wg.Wait()

	if completed == 0 {
		t.Fatalf("no TRUNCATE checkpoint completed under load (%d incomplete) — checkpoint starved", incomplete)
	}
	t.Logf("checkpoints: %d completed, %d busy; rows written: %d", completed, incomplete, atomic.LoadInt64(&wrote))

	// No data loss: every committed row is present.
	want := int64(writers * perWriter)
	if got := atomic.LoadInt64(&wrote); got != want {
		t.Fatalf("writers wrote %d rows, want %d", got, want)
	}
	var n int64
	if err := c.QueryRow(`SELECT count(*) FROM t`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != want {
		t.Fatalf("row count %d after concurrent checkpoint, want %d (frames lost)", n, want)
	}

	// Durable + uncorrupted: a fresh open reads every row back.
	w.Close()
	c.Close()
	re, err := sql.Open("sqlite", "file:"+path)
	if err != nil {
		t.Fatal(err)
	}
	defer re.Close()
	var n2 int64
	if err := re.QueryRow(`SELECT count(*) FROM t`).Scan(&n2); err != nil {
		t.Fatal(err)
	}
	if n2 != want {
		t.Fatalf("reopened DB has %d rows, want %d", n2, want)
	}
}

func isBusy(err error) bool {
	if err == nil {
		return false
	}
	s := err.Error()
	return strings.Contains(s, "database is locked") || strings.Contains(s, "SQLITE_BUSY") || strings.Contains(s, "database table is locked")
}
