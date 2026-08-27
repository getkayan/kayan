package domain

import "errors"

// Portable storage errors. Adapters wrap these values so callers can use
// errors.Is without depending on an ORM or database driver.
var (
	ErrNotFound = errors.New("domain: not found")
	ErrConflict = errors.New("domain: conflict")
	ErrExpired  = errors.New("domain: expired")
)
