package domain

import (
	"fmt"

	"golang.org/x/crypto/bcrypt"
)

// DefaultBcryptCost is the work factor used when none is given.
//
// 12 is roughly 250ms per hash on current hardware — high enough to make
// offline cracking expensive, low enough that a login burst does not exhaust
// CPU. Raise it as hardware improves; bcrypt stores the cost in the hash, so
// existing hashes keep verifying.
const DefaultBcryptCost = 12

// BcryptHasher hashes secrets with bcrypt.
//
// It implements [Hasher] and is the default wherever Kayan hashes a secret.
// To use argon2id, scrypt, or an external service instead, implement [Hasher]
// and pass it to whichever component accepts one — nothing here is required.
type BcryptHasher struct {
	Cost int
}

var _ Hasher = (*BcryptHasher)(nil)

// NewBcryptHasher returns a hasher with the given cost. A cost of zero selects
// [DefaultBcryptCost].
func NewBcryptHasher(cost int) *BcryptHasher {
	if cost == 0 {
		cost = DefaultBcryptCost
	}
	return &BcryptHasher{Cost: cost}
}

// Hash returns the bcrypt hash of password.
func (h *BcryptHasher) Hash(password string) (string, error) {
	// bcrypt silently truncates at 72 bytes, so a long passphrase would have
	// its tail ignored — two distinct secrets sharing a 72-byte prefix would
	// both verify. Reject rather than truncate.
	if len(password) > 72 {
		return "", fmt.Errorf("domain: secret exceeds bcrypt's 72-byte limit")
	}

	bytes, err := bcrypt.GenerateFromPassword([]byte(password), h.Cost)
	if err != nil {
		return "", fmt.Errorf("domain: bcrypt hash: %w", err)
	}
	return string(bytes), nil
}

// Compare reports whether password matches hash.
//
// bcrypt's comparison is constant-time with respect to the hash contents.
func (h *BcryptHasher) Compare(password, hash string) bool {
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(password)) == nil
}
