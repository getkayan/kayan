package flow

import (
	"github.com/getkayan/kayan/core/domain"
)

// BcryptHasher hashes secrets with bcrypt.
//
// Deprecated: use [domain.BcryptHasher]. It moved to core/domain because it is
// a [domain.Hasher] implementation with no dependency on this package, and
// other packages that hash secrets could not reach it here. This alias keeps
// existing wiring working.
type BcryptHasher = domain.BcryptHasher

// NewBcryptHasher returns a bcrypt hasher. A cost of zero selects
// [domain.DefaultBcryptCost].
//
// Deprecated: use [domain.NewBcryptHasher].
func NewBcryptHasher(cost int) *domain.BcryptHasher {
	return domain.NewBcryptHasher(cost)
}
