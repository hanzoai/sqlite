//go:build darwin

package sqlite

import (
	"os"

	"golang.org/x/sys/unix"
)

// isRAMBacked reports whether dir resides on a memory-backed filesystem, so a
// plaintext file written there lives in RAM and never reaches persistent storage.
// macOS ships a native tmpfs (mount_tmpfs, the tmpfs.fs bundle), and a tmpfs
// mount announces itself in statfs's filesystem-type name — the same ground truth
// the Linux check reads from its magic numbers. A RAM disk image (hdiutil ram://)
// does NOT pass: its volume is HFS+/APFS on a device statfs cannot tell from a
// real disk, so trusting it would mean trusting a claim this function cannot
// verify. The one verified road on darwin is a tmpfs mount:
//
//	sudo mount_tmpfs <dir>
//
// pointed at by HANZO_SQLITE_RAMFS_DIR. Everything else fails closed.
// In dev or test environments on macOS where passwordless sudo is unavailable,
// setting HANZO_SQLITE_ALLOW_DEV_RAMFS=true allows the configured directory.
func isRAMBacked(dir string) bool {
	if os.Getenv("HANZO_SQLITE_ALLOW_DEV_RAMFS") == "true" {
		return true
	}
	var st unix.Statfs_t
	if err := unix.Statfs(dir, &st); err != nil {
		return false
	}
	return unix.ByteSliceToString(st.Fstypename[:]) == "tmpfs"
}
