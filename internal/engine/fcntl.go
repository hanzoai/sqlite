// Copyright 2024 The Sqlite Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package sqlite // import "github.com/hanzoai/sqlite/internal/engine"

import (
	"unsafe"

	sqlite3 "github.com/hanzoai/sqlite/internal/engine/lib"
	"github.com/hanzoai/sqlite/internal/libc"
)

// Access to sqlite3_file_control
type FileControl interface {
	// Set or query SQLITE_FCNTL_PERSIST_WAL, returns set mode or query result
	FileControlPersistWAL(dbName string, mode int) (int, error)
	// Query SQLITE_FCNTL_DATA_VERSION, returns the pager-cache data version
	// for dbName. The value changes whenever the contents of the database
	// file change, which makes it suitable for cache-invalidation use cases.
	// See
	// https://www.sqlite.org/c3ref/c_fcntl_begin_atomic_write.html#sqlitefcntldataversion.
	FileControlDataVersion(dbName string) (uint32, error)
}

var _ FileControl = (*conn)(nil)

func (c *conn) FileControlPersistWAL(dbName string, mode int) (int, error) {
	pi32 := c.tls.Alloc(4)
	defer c.tls.Free(4)

	*(*int32)(unsafe.Pointer(pi32)) = int32(mode)
	err := c.fileControl(dbName, sqlite3.SQLITE_FCNTL_PERSIST_WAL, pi32)
	return int(*(*int32)(unsafe.Pointer(pi32))), err
}

func (c *conn) FileControlDataVersion(dbName string) (uint32, error) {
	pu32 := c.tls.Alloc(4)
	defer c.tls.Free(4)

	*(*uint32)(unsafe.Pointer(pu32)) = 0
	err := c.fileControl(dbName, sqlite3.SQLITE_FCNTL_DATA_VERSION, pu32)
	return *(*uint32)(unsafe.Pointer(pu32)), err
}

// fileControlReserveBytes sets SQLITE_FCNTL_RESERVE_BYTES on "main" to n. The
// SQLCipher page format carries an 80-byte per-page trailer (IV+HMAC), so the
// pure-Go codec VFS needs SQLite to leave that many reserve bytes at the end of
// every page. This must run before the first page-1 write on a NEW database; on
// an existing one the reserve already travels in header byte 20 and this just
// confirms it. The DSN param `_reserve_bytes=N` (handled in applyQueryParams
// before any writing pragma) is how the keyed codec path sets it.
func (c *conn) fileControlReserveBytes(n int) error {
	pi32 := c.tls.Alloc(4)
	defer c.tls.Free(4)

	*(*int32)(unsafe.Pointer(pi32)) = int32(n)
	return c.fileControl("main", sqlite3.SQLITE_FCNTL_RESERVE_BYTES, pi32)
}

func (c *conn) fileControl(dbName string, op int, pArg uintptr) error {
	zDbName, err := libc.CString(dbName)
	if err != nil {
		return err
	}
	defer c.free(zDbName)

	if rc := sqlite3.Xsqlite3_file_control(c.tls, c.db, zDbName, int32(op), pArg); rc != sqlite3.SQLITE_OK {
		return c.errstr(rc)
	}

	return nil
}
