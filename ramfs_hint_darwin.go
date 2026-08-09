//go:build darwin

package sqlite

// ramfsHint is this platform's road to RAM-backed scratch, in the words to type.
// macOS ships tmpfs but mounts none by default, and an hdiutil RAM disk cannot be
// verified (HFS+/APFS on a device statfs cannot tell from a real one).
const ramfsHint = "\n\nmacOS ships tmpfs but does not mount one:\n" +
	"    sudo mount_tmpfs /tmp/hanzo-ramfs && export HANZO_SQLITE_RAMFS_DIR=/tmp/hanzo-ramfs\n" +
	"An hdiutil RAM disk does not qualify: statfs cannot tell it from a real disk."
