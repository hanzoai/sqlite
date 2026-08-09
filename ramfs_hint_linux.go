//go:build linux

package sqlite

// ramfsHint is the one road to a RAM-backed scratch dir on this platform, in the
// words the operator has to type. Most Linux hosts already have /dev/shm and
// never read this; a container started without it is the case that does.
const ramfsHint = "\n\nMost Linux hosts mount a tmpfs at /dev/shm already. In a container without one:\n" +
	"    mount -t tmpfs -o size=64m tmpfs /dev/shm\n" +
	"or point HANZO_SQLITE_RAMFS_DIR at any tmpfs/ramfs mount."
