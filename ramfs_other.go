//go:build !linux

package sqlite

// isRAMBacked can only be verified on Linux (via statfs), where the encrypted
// stores run. Off Linux it reports false, so the envelope's scratch resolver
// fails closed rather than risk materialising a decrypted database on persistent
// storage. A non-Linux host that needs the pure-Go codec must provide a verified
// RAM-backed mount and Linux-style statfs; until then, use the CGO+libsqlcipher
// backend there.
func isRAMBacked(dir string) bool { return false }
