//go:build linux

package sqlite

// ramfsHint is this platform's road to RAM-backed scratch. Most hosts have
// /dev/shm already; a container started without one does not.
const ramfsHint = "\n\nMost Linux hosts mount tmpfs at /dev/shm. In a container without one:\n" +
	"    mount -t tmpfs -o size=64m tmpfs /dev/shm\n" +
	"or point HANZO_SQLITE_RAMFS_DIR at any tmpfs/ramfs mount."
