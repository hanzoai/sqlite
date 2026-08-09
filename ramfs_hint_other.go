//go:build !darwin && !linux

package sqlite

// ramfsHint is empty where no verified road is known. Better than inventing one.
const ramfsHint = ""
