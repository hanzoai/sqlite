//go:build linux

package sqlite

import "golang.org/x/sys/unix"

// isRAMBacked reports whether dir resides on a memory-backed filesystem — tmpfs or
// ramfs — so a plaintext file written there lives in RAM and never reaches
// persistent storage. It is how the pure-Go SQLCipher envelope refuses to
// materialise a decrypted database anywhere it could be read from a disk snapshot.
func isRAMBacked(dir string) bool {
	var st unix.Statfs_t
	if err := unix.Statfs(dir, &st); err != nil {
		return false
	}
	return st.Type == unix.TMPFS_MAGIC || st.Type == unix.RAMFS_MAGIC
}
