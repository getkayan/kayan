package scim

import (
	"errors"
	"fmt"
)

var (
	ErrNotFound      = errors.New("scim: resource not found")
	ErrInvalidFilter = errors.New("scim: invalid filter")
	ErrUnsupported   = errors.New("scim: operation not supported")
	ErrConflict      = errors.New("scim: resource already exists")

	// ErrFilterUnsupported reports that a storage implementation cannot
	// evaluate the supplied filter.
	//
	// Implementations must return this rather than ignoring the filter and
	// returning every resource: a caller that filtered a list expects a subset,
	// and silently widening it discloses resources they did not ask for.
	ErrFilterUnsupported = errors.New("scim: filtering is not supported by this storage implementation")
)

// ErrorResponse represents a SCIM error response (RFC 7644 Section 3.12)
type ErrorResponse struct {
	Schemas  []string `json:"schemas"`
	Status   string   `json:"status"`
	ScimType string   `json:"scimType,omitempty"`
	Detail   string   `json:"detail"`
}

func (e *ErrorResponse) Error() string {
	return fmt.Sprintf("scim: %s (%s): %s", e.Status, e.ScimType, e.Detail)
}

func NewError(status, scimType, detail string) *ErrorResponse {
	return &ErrorResponse{
		Schemas:  []string{"urn:ietf:params:scim:api:messages:2.0:Error"},
		Status:   status,
		ScimType: scimType,
		Detail:   detail,
	}
}
