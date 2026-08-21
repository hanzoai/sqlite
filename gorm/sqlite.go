// Package sqlite speaks SQLite to gorm over github.com/hanzoai/sqlite.
//
// It is a fork of gorm.io/driver/sqlite, which blank-imports mattn/go-sqlite3
// purely to register a driver name. Both that and the facade's cgo backend
// vendor the SQLite amalgamation, so a binary linking the two fails at the
// linker under cgo — which is the whole reason this exists.
//
// It is a bridge, not a destination: hanzoai/orm is the estate's ORM, and this
// module retires when nothing imports gorm.
package sqlite

import (
	"context"
	"strconv"

	"gorm.io/gorm/callbacks"

	driver "github.com/hanzoai/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
	"gorm.io/gorm/logger"
	"gorm.io/gorm/migrator"
	"gorm.io/gorm/schema"
)

// Dialector speaks SQLite to gorm over github.com/hanzoai/sqlite, which is the
// one engine it opens. Upstream carries a field naming some other registered
// driver; it is absent here, so an example that sets it fails to compile rather
// than quietly opening a database on different terms.
type Dialector struct {
	DSN  string
	Conn gorm.ConnPool
}

type Config struct {
	DSN  string
	Conn gorm.ConnPool
}

// pragmas is the driver's profile WITHOUT foreign_keys, and that omission is the
// whole reason this list is spelled out rather than taken from the driver.
//
// The migrator alters a column by rebuilding the table — create, copy, DROP the
// original, rename — which SQLite refuses while a foreign key references it. The
// migrator's own guard toggles `PRAGMA foreign_keys` on the *sql.DB, but the
// pragma is per CONNECTION and the rebuild runs in a transaction the pool may
// serve from a different one. Measured on both backends: DropColumn fails every
// time, and AlterColumn fails whenever the pool hands the transaction a second
// connection.
//
// Upstream never met this: a bare sql.Open leaves foreign keys off, so the
// guard's enabled-branch was dead code. Enforcing them here woke it up. A caller
// that wants them enforced brings its own pool through Conn.
var pragmas = []driver.Pragma{
	{Name: "busy_timeout", Value: "10000"},
	{Name: "journal_mode", Value: "WAL"},
	{Name: "journal_size_limit", Value: "200000000"},
	{Name: "synchronous", Value: "NORMAL"},
	{Name: "temp_store", Value: "MEMORY"},
	{Name: "cache_size", Value: "-32000"},
}

// Open addresses dsn. The pragmas above are applied AFTER anything in dsn and
// therefore win, and there is no field to change them — a caller who needs a
// different profile builds its own pool and passes it as Conn.
func Open(dsn string) gorm.Dialector {
	return &Dialector{DSN: dsn}
}

func New(config Config) gorm.Dialector {
	return &Dialector{DSN: config.DSN, Conn: config.Conn}
}

func (dialector Dialector) Name() string {
	return "sqlite"
}

func (dialector Dialector) Initialize(db *gorm.DB) (err error) {
	// A caller who brought their own pool has already decided how it opens.
	// Otherwise open through the driver's own door rather than by driver name:
	// sql.Open applies no pragmas, so a bare open leaves the database on the
	// rollback journal and takes whichever busy_timeout the backend defaults to.
	if dialector.Conn != nil {
		db.ConnPool = dialector.Conn
	} else {
		conn, err := driver.OpenPragma(dialector.DSN, pragmas)
		if err != nil {
			return err
		}
		db.ConnPool = conn
	}

	var version string
	if err := db.ConnPool.QueryRowContext(context.Background(), "select sqlite_version()").Scan(&version); err != nil {
		return err
	}
	// https://www.sqlite.org/releaselog/3_35_0.html
	if compareVersion(version, "3.35.0") >= 0 {
		callbacks.RegisterDefaultCallbacks(db, &callbacks.Config{
			CreateClauses:        []string{"INSERT", "VALUES", "ON CONFLICT", "RETURNING"},
			UpdateClauses:        []string{"UPDATE", "SET", "FROM", "WHERE", "RETURNING"},
			DeleteClauses:        []string{"DELETE", "FROM", "WHERE", "RETURNING"},
			LastInsertIDReversed: true,
		})
	} else {
		callbacks.RegisterDefaultCallbacks(db, &callbacks.Config{
			LastInsertIDReversed: true,
		})
	}

	for k, v := range dialector.ClauseBuilders() {
		if _, ok := db.ClauseBuilders[k]; !ok {
			db.ClauseBuilders[k] = v
		}
	}
	return
}

func (dialector Dialector) ClauseBuilders() map[string]clause.ClauseBuilder {
	return map[string]clause.ClauseBuilder{
		"INSERT": func(c clause.Clause, builder clause.Builder) {
			if insert, ok := c.Expression.(clause.Insert); ok {
				if stmt, ok := builder.(*gorm.Statement); ok {
					stmt.WriteString("INSERT ")
					if insert.Modifier != "" {
						stmt.WriteString(insert.Modifier)
						stmt.WriteByte(' ')
					}

					stmt.WriteString("INTO ")
					if insert.Table.Name == "" {
						stmt.WriteQuoted(stmt.Table)
					} else {
						stmt.WriteQuoted(insert.Table)
					}
					return
				}
			}

			c.Build(builder)
		},
		"LIMIT": func(c clause.Clause, builder clause.Builder) {
			if limit, ok := c.Expression.(clause.Limit); ok {
				var lmt = -1
				if limit.Limit != nil && *limit.Limit >= 0 {
					lmt = *limit.Limit
				}
				if lmt >= 0 || limit.Offset > 0 {
					builder.WriteString("LIMIT ")
					builder.WriteString(strconv.Itoa(lmt))
				}
				if limit.Offset > 0 {
					builder.WriteString(" OFFSET ")
					builder.WriteString(strconv.Itoa(limit.Offset))
				}
			}
		},
		"FOR": func(c clause.Clause, builder clause.Builder) {
			if _, ok := c.Expression.(clause.Locking); ok {
				// SQLite3 does not support row-level locking.
				return
			}
			c.Build(builder)
		},
	}
}

func (dialector Dialector) DefaultValueOf(field *schema.Field) clause.Expression {
	if field.AutoIncrement {
		return clause.Expr{SQL: "NULL"}
	}

	// doesn't work, will raise error
	return clause.Expr{SQL: "DEFAULT"}
}

func (dialector Dialector) Migrator(db *gorm.DB) gorm.Migrator {
	return Migrator{migrator.Migrator{Config: migrator.Config{
		DB:                          db,
		Dialector:                   dialector,
		CreateIndexAfterCreateTable: true,
	}}}
}

func (dialector Dialector) BindVarTo(writer clause.Writer, stmt *gorm.Statement, v interface{}) {
	writer.WriteByte('?')
}

func (dialector Dialector) QuoteTo(writer clause.Writer, str string) {
	var (
		underQuoted, selfQuoted bool
		continuousBacktick      int8
		shiftDelimiter          int8
	)

	for _, v := range []byte(str) {
		switch v {
		case '`':
			continuousBacktick++
			if continuousBacktick == 2 {
				writer.WriteString("``")
				continuousBacktick = 0
			}
		case '.':
			if continuousBacktick > 0 || !selfQuoted {
				shiftDelimiter = 0
				underQuoted = false
				continuousBacktick = 0
				writer.WriteString("`")
			}
			writer.WriteByte(v)
			continue
		default:
			if shiftDelimiter-continuousBacktick <= 0 && !underQuoted {
				writer.WriteString("`")
				underQuoted = true
				if selfQuoted = continuousBacktick > 0; selfQuoted {
					continuousBacktick -= 1
				}
			}

			for ; continuousBacktick > 0; continuousBacktick -= 1 {
				writer.WriteString("``")
			}

			writer.WriteByte(v)
		}
		shiftDelimiter++
	}

	if continuousBacktick > 0 && !selfQuoted {
		writer.WriteString("``")
	}
	writer.WriteString("`")
}

func (dialector Dialector) Explain(sql string, vars ...interface{}) string {
	return logger.ExplainSQL(sql, nil, `"`, vars...)
}

func (dialector Dialector) DataTypeOf(field *schema.Field) string {
	switch field.DataType {
	case schema.Bool:
		return "numeric"
	case schema.Int, schema.Uint:
		if field.AutoIncrement {
			// doesn't check `PrimaryKey`, to keep backward compatibility
			// https://www.sqlite.org/autoinc.html
			return "integer PRIMARY KEY AUTOINCREMENT"
		} else {
			return "integer"
		}
	case schema.Float:
		return "real"
	case schema.String:
		return "text"
	case schema.Time:
		// Distinguish between schema.Time and tag time
		if val, ok := field.TagSettings["TYPE"]; ok {
			return val
		} else {
			return "datetime"
		}
	case schema.Bytes:
		return "blob"
	}

	return string(field.DataType)
}

func (dialectopr Dialector) SavePoint(tx *gorm.DB, name string) error {
	tx.Exec("SAVEPOINT " + name)
	return nil
}

func (dialectopr Dialector) RollbackTo(tx *gorm.DB, name string) error {
	tx.Exec("ROLLBACK TO SAVEPOINT " + name)
	return nil
}

func compareVersion(version1, version2 string) int {
	n, m := len(version1), len(version2)
	i, j := 0, 0
	for i < n || j < m {
		x := 0
		for ; i < n && version1[i] != '.'; i++ {
			x = x*10 + int(version1[i]-'0')
		}
		i++
		y := 0
		for ; j < m && version2[j] != '.'; j++ {
			y = y*10 + int(version2[j]-'0')
		}
		j++
		if x > y {
			return 1
		}
		if x < y {
			return -1
		}
	}
	return 0
}
