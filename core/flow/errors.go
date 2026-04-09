package flow

import "errors"

var (
	// ErrIdentityAlreadyExists is returned when a registration attempt matches an existing identity
	// but the duplicate policy prevents automatic linking/capture.
	ErrIdentityAlreadyExists = errors.New("registration: identity already exists")
)
