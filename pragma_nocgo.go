//go:build !cgo || sqlite_purego

package sqlite

import (
	"fmt"
	"strings"
)

// PragmaDSN builds an unencrypted `file:` DSN for path that applies pragmas in
// modernc's `_pragma=NAME(VALUE)` syntax — the form modernc actually applies.
// The path is percent-escaped (escapeDBPath) so a '?' or '#' in it cannot
// terminate the path early and strip the query. This is the CGO-off default
// engine; keyed/encrypted opens go through OpenDB/DSN instead.
func PragmaDSN(path string, pragmas []Pragma) string {
	parts := make([]string, 0, len(pragmas))
	for _, p := range pragmas {
		parts = append(parts, "_pragma="+p.Name+"("+p.Value+")")
	}
	return fmt.Sprintf("file:%s?%s", escapeDBPath(path), strings.Join(parts, "&"))
}
