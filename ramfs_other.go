//go:build !linux && !darwin

package sqlite

// isRAMBacked can only be verified where statfs names the filesystem — Linux
// (magic numbers) and darwin (type name) have their own files. Everywhere else
// it reports false, so the envelope's scratch resolver fails closed rather than
// risk materialising a decrypted database on persistent storage. A host here
// that needs the pure-Go codec must first gain a verified check like those two;
// until then, use the CGO+libsqlcipher backend.
func isRAMBacked(dir string) bool { return false }
