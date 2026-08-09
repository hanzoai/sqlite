//go:build darwin

package sqlite

// ramfsHint is the one road to a RAM-backed scratch dir on this platform, in the
// words the operator has to type.
//
// It exists because the refusal was true and unhelpful in the same breath. The
// message named /dev/shm, which macOS does not have, and HANZO_SQLITE_RAMFS_DIR,
// which macOS cannot satisfy without a mount — so the reader learned that their
// machine was wrong and nothing about how to make it right. Faced with that, the
// obvious guess is an hdiutil RAM disk, which IS memory-backed and which this
// package correctly refuses (HFS+/APFS on a device statfs cannot tell from a real
// one), so the guess costs a detour and ends where it started.
//
// macOS does ship tmpfs — /sbin/mount_tmpfs, the tmpfs.fs bundle — and that is
// the whole answer. It needs privileges, which is worth saying out loud rather
// than letting "Operation not permitted" be the next surprise.
const ramfsHint = "\n\nmacOS ships tmpfs but does not mount one by default:\n" +
	"    sudo mount_tmpfs /tmp/hanzo-ramfs && export HANZO_SQLITE_RAMFS_DIR=/tmp/hanzo-ramfs\n" +
	"An hdiutil RAM disk does NOT qualify: its volume is HFS+/APFS and statfs cannot\n" +
	"tell it from a real disk, so this package cannot verify the claim and refuses it."
