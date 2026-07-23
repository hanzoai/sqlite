module github.com/hanzoai/sqlite

go 1.26.4

require (
	github.com/hanzoai/csqlite v0.1.0
	github.com/hanzoai/sqlcipher v0.1.1
	github.com/luxfi/crypto v1.19.26
	golang.org/x/crypto v0.52.0
	golang.org/x/sys v0.45.0
	modernc.org/sqlite v1.48.0
)

require (
	github.com/dustin/go-humanize v1.0.1 // indirect
	github.com/google/uuid v1.6.0 // indirect
	github.com/mattn/go-isatty v0.0.21 // indirect
	github.com/ncruces/go-strftime v1.0.0 // indirect
	github.com/remyoudompheng/bigfft v0.0.0-20230129092748-24d4a6f8daec // indirect
	golang.org/x/tools v0.43.0 // indirect
	modernc.org/libc v1.70.0 // indirect
	modernc.org/mathutil v1.7.1 // indirect
	modernc.org/memory v1.11.0 // indirect
)

// TEMPORARY (pre-release pin): until hanzoai/sqlcipher is tagged v0.1.1 (the
// EmptyPlaintext patch), resolve it from the sibling checkout so this branch
// builds standalone. Remove at release, when v0.1.1 is fetchable.
replace github.com/hanzoai/sqlcipher => ../sqlcipher
