package sqlite_test

import (
	"errors"
	"testing"

	sqlite "github.com/hanzoai/sqlite/gorm"
	"gorm.io/gorm"
)

// open returns a gorm handle on a private database, with error translation on —
// gorm consults Translate only when a caller asks it to.
//
// The pool is closed when the test ends. A shared-cache in-memory database lives
// as long as a connection to it does, so leaving one open carries the tables
// into the next run and `-count=2` fails on "table already exists".
func open(t *testing.T) *gorm.DB {
	t.Helper()
	db, err := gorm.Open(sqlite.Open("file:"+t.Name()+"?mode=memory&cache=shared"),
		&gorm.Config{TranslateError: true})
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() {
		if pool, err := db.DB(); err == nil {
			_ = pool.Close()
		}
	})
	return db
}

// TestTranslate drives the real engine rather than a hand-built error, which is
// the only way to know the driver still recognises what it is handed: a
// predicate that stopped matching would look exactly like a passing unit test
// over a fabricated value.
func TestTranslate(t *testing.T) {
	for _, c := range []struct {
		name, ddl, first, again string
		want                    error
		enforceFK               bool
	}{
		{
			name:  "unique",
			ddl:   "CREATE TABLE u (v TEXT UNIQUE)",
			first: "INSERT INTO u VALUES ('x')", again: "INSERT INTO u VALUES ('x')",
			want: gorm.ErrDuplicatedKey,
		},
		{
			name:  "primary key",
			ddl:   "CREATE TABLE p (id INTEGER PRIMARY KEY)",
			first: "INSERT INTO p VALUES (1)", again: "INSERT INTO p VALUES (1)",
			want: gorm.ErrDuplicatedKey,
		},
		{
			name:  "foreign key",
			ddl:   "CREATE TABLE parent (id INTEGER PRIMARY KEY); CREATE TABLE child (p INTEGER REFERENCES parent(id))",
			first: "SELECT 1", again: "INSERT INTO child VALUES (99)",
			want: gorm.ErrForeignKeyViolated,
			// This dialector does not enforce foreign keys (see `pragmas`), so the
			// caller turns them on for its own pool — which is also the supported
			// way to get them enforced, exercised here rather than described.
			enforceFK: true,
		},
	} {
		t.Run(c.name, func(t *testing.T) {
			db := open(t)
			if c.enforceFK {
				// One connection, so the pragma the next statement needs is the
				// one this statement set: it is per connection, not per pool.
				pool, err := db.DB()
				if err != nil {
					t.Fatalf("pool: %v", err)
				}
				pool.SetMaxOpenConns(1)
				if err := db.Exec("PRAGMA foreign_keys = ON").Error; err != nil {
					t.Fatalf("enable foreign keys: %v", err)
				}
			}
			for _, s := range []string{c.ddl, c.first} {
				if err := db.Exec(s).Error; err != nil {
					t.Fatalf("setup %q: %v", s, err)
				}
			}
			err := db.Exec(c.again).Error
			if !errors.Is(err, c.want) {
				t.Fatalf("%q returned %v, want %v", c.again, err, c.want)
			}
		})
	}
}

// TestTranslateKeepsWhatItHasNoWordFor is the other half: a refusal gorm has no
// vocabulary for must arrive intact rather than be flattened into a constraint.
func TestTranslateKeepsWhatItHasNoWordFor(t *testing.T) {
	err := open(t).Exec("SELECT * FROM absent").Error
	if err == nil {
		t.Fatal("querying a table that does not exist returned no error")
	}
	for _, w := range []error{gorm.ErrDuplicatedKey, gorm.ErrForeignKeyViolated} {
		if errors.Is(err, w) {
			t.Fatalf("a missing table was translated to %v", w)
		}
	}
}
