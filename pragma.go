package sqlite

// Connection-tuning surface — one pragma set, encoded per backend.
//
// The two backends express connection pragmas with DIFFERENT DSN syntax:
//
//	modernc (!cgo):  ?_pragma=busy_timeout(10000)&_pragma=journal_mode(WAL)&...
//	mattn   (cgo):   ?_busy_timeout=10000&_journal_mode=WAL&...
//
// A DSN written for one backend is silently IGNORED by the other (mattn drops
// unknown `_pragma=` params; modernc drops unknown `_busy_timeout=` params), so
// a hardcoded single-form DSN loses its pragmas — no WAL, no busy_timeout —
// whenever the binary is built for the other backend (e.g. Base is CGO=0 but is
// embedded into commerce's CGO=1 build). PragmaDSN encodes the pragmas in the
// ACTIVE backend's syntax (pragma_cgo.go / pragma_nocgo.go) so the same pragma
// set applies under both.

// Pragma is one SQLite PRAGMA (name + value) applied at connection-open time via
// the DSN.
type Pragma struct{ Name, Value string }

// DefaultPragmas is the canonical Hanzo embedded-SQLite connection tuning. Order
// matters: busy_timeout MUST lead so a connection blocks on a busy database
// before journal_mode=WAL is set (WAL cannot be enabled while another
// connection holds the database). This is the single source of truth for the
// unencrypted default-connect DSN used across Hanzo Base (core + multitenant
// store) — treat it as read-only.
var DefaultPragmas = []Pragma{
	{Name: "busy_timeout", Value: "10000"},
	{Name: "journal_mode", Value: "WAL"},
	{Name: "journal_size_limit", Value: "200000000"},
	{Name: "synchronous", Value: "NORMAL"},
	{Name: "foreign_keys", Value: "ON"},
	{Name: "temp_store", Value: "MEMORY"},
	{Name: "cache_size", Value: "-32000"},
}
