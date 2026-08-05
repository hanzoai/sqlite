//go:build darwin

package sqlite

import (
	"testing"

	"golang.org/x/sys/unix"
)

// TestRAMBackedRefusesTheSystemVolume pins the fail-closed side on darwin: the
// sealed system volume is APFS by construction, never tmpfs, so it must never be
// accepted as scratch for a decrypted database.
func TestRAMBackedRefusesTheSystemVolume(t *testing.T) {
	if isRAMBacked("/") {
		t.Fatal("isRAMBacked accepted the APFS system volume — plaintext scratch would reach persistent storage")
	}
}

// TestRAMBackedRecognisesTmpfs proves the positive side against a real mount: if
// this machine has a tmpfs mounted anywhere, its mountpoint must be accepted.
// With no tmpfs present the test skips — creating one needs root
// (sudo mount_tmpfs <dir>), which a test must not assume.
func TestRAMBackedRecognisesTmpfs(t *testing.T) {
	n, err := unix.Getfsstat(nil, unix.MNT_NOWAIT)
	if err != nil {
		t.Fatalf("Getfsstat count: %v", err)
	}
	mounts := make([]unix.Statfs_t, n)
	if _, err := unix.Getfsstat(mounts, unix.MNT_NOWAIT); err != nil {
		t.Fatalf("Getfsstat: %v", err)
	}
	for _, m := range mounts {
		if unix.ByteSliceToString(m.Fstypename[:]) != "tmpfs" {
			continue
		}
		dir := unix.ByteSliceToString(m.Mntonname[:])
		if !isRAMBacked(dir) {
			t.Fatalf("isRAMBacked refused the tmpfs mount at %s", dir)
		}
		return
	}
	t.Skip("no tmpfs mounted; create one with: sudo mount_tmpfs <dir>")
}
