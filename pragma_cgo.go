//go:build cgo

package sqlite

import (
	"fmt"
	"strings"
)

// PragmaDSN builds an unencrypted `file:` DSN for path that applies pragmas in
// csqlite's `_NAME=VALUE` syntax. csqlite recognises _busy_timeout,
// _journal_mode, _synchronous, _foreign_keys and _cache_size and silently
// ignores any other parameter — so pragmas it cannot express as a DSN param
// (journal_size_limit, temp_store) are inert here but harmless, while the
// correctness-critical ones (busy_timeout, WAL) DO apply. The path is
// percent-escaped (escapeDBPath) so a '?'/'#' in it cannot strip the query. No
// key is added — keyed/encrypted opens go through OpenDB/DSN.
func PragmaDSN(path string, pragmas []Pragma) string {
	parts := make([]string, 0, len(pragmas))
	for _, p := range pragmas {
		parts = append(parts, "_"+p.Name+"="+p.Value)
	}
	return fmt.Sprintf("file:%s?%s", escapeDBPath(path), strings.Join(parts, "&"))
}
