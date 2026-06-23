//go:build !cgo

// Package sqlite is a CGO + SQLCipher SQLite driver (go-sqlite3). Without CGO it
// is an empty stub so dependents still typecheck under CGO-off linters; the real
// build uses CGO_ENABLED=1 -tags sqlcipher. See the cgo-tagged files for the impl.
package sqlite
