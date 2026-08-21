package sqlite

import (
	driver "github.com/hanzoai/sqlite"
	"gorm.io/gorm"
)

// Translate renders a driver error in gorm's own vocabulary, leaving anything
// it has no word for untouched.
//
// The question "which constraint did this violate" belongs to the driver, which
// is the only layer that sees the engine's extended result code, so it is asked
// there rather than answered a second time here. Upstream read the code out by
// marshalling the error to JSON and back — the one way to reach it without
// naming a cgo-only error type, and unnecessary once the driver answers.
func (dialector Dialector) Translate(err error) error {
	switch {
	case driver.IsConstraintUnique(err), driver.IsConstraintPrimaryKey(err):
		return gorm.ErrDuplicatedKey
	case driver.IsConstraintForeignKey(err):
		return gorm.ErrForeignKeyViolated
	}
	return err
}
