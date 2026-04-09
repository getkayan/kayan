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
