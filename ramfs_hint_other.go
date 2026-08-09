//go:build !darwin && !linux

package sqlite

// ramfsHint is empty where this package knows no verified road to RAM-backed
// scratch. Saying nothing beats inventing a command that does not exist here.
const ramfsHint = ""
