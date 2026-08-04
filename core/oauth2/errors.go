package oauth2

import (
	"errors"
	"fmt"
	"net/http"
)

// Error is an OAuth 2.0 protocol error (RFC 6749 sections 4.1.2.1 and 5.2).
//
// It marshals directly to the wire format, and reports the status code the
// specification assigns, so the caller can respond without a translation table:
//
//	var oerr *oauth2.Error
//	if errors.As(err, &oerr) {
//	    w.Header().Set("Content-Type", "application/json")
//	    w.WriteHeader(oerr.StatusCode())
//	    json.NewEncoder(w).Encode(oerr)
//	}
//
// Kayan never writes to an http.ResponseWriter itself; the shape above is the
// caller's to implement.
type Error struct {
	// Code is the error identifier that goes on the wire, such as
	// "invalid_grant". Required.
	Code string `json:"error"`

	// Description is a human-readable explanation. It reaches the client, so
	// it must not disclose whether a client ID exists, which credential was
	// wrong, or any other detail useful for enumeration.
	Description string `json:"error_description,omitempty"`

	// URI optionally points at documentation for this error.
	URI string `json:"error_uri,omitempty"`

	// State echoes the authorization request's state parameter. Set only for
	// errors returned via redirect.
	State string `json:"state,omitempty"`

	status int
	cause  error
}

// Sentinel protocol errors.
//
// These are values, not templates: [Error.WithDescription] and
// [Error.WithCause] return copies, so a sentinel is never mutated and can be
// compared with errors.Is from concurrent requests.
var (
	// ErrInvalidRequest: the request is malformed or has a duplicate parameter.
	ErrInvalidRequest = &Error{Code: "invalid_request", status: http.StatusBadRequest}

	// ErrInvalidClient: client authentication failed.
	ErrInvalidClient = &Error{Code: "invalid_client", status: http.StatusUnauthorized}

	// ErrInvalidGrant: the grant or refresh token is invalid, expired, revoked,
	// or was issued to another client.
	ErrInvalidGrant = &Error{Code: "invalid_grant", status: http.StatusBadRequest}

	// ErrUnauthorizedClient: this client may not use this grant type.
	ErrUnauthorizedClient = &Error{Code: "unauthorized_client", status: http.StatusBadRequest}

	// ErrUnsupportedGrantType: the authorization server does not support this grant.
	ErrUnsupportedGrantType = &Error{Code: "unsupported_grant_type", status: http.StatusBadRequest}

	// ErrUnsupportedResponseType: the authorization server does not support this
	// response type.
	ErrUnsupportedResponseType = &Error{Code: "unsupported_response_type", status: http.StatusBadRequest}

	// ErrInvalidScope: the requested scope is unknown, malformed, or exceeds
	// what was granted.
	ErrInvalidScope = &Error{Code: "invalid_scope", status: http.StatusBadRequest}

	// ErrAccessDenied: the resource owner or authorization server refused the
	// request.
	ErrAccessDenied = &Error{Code: "access_denied", status: http.StatusForbidden}

	// ErrServerError: an unexpected condition prevented fulfilling the request.
	ErrServerError = &Error{Code: "server_error", status: http.StatusInternalServerError}

	// ErrTemporarilyUnavailable: the server is overloaded or under maintenance.
	ErrTemporarilyUnavailable = &Error{Code: "temporarily_unavailable", status: http.StatusServiceUnavailable}

	// ErrInvalidToken: the access token is expired, revoked, or malformed
	// (RFC 6750 section 3.1).
	ErrInvalidToken = &Error{Code: "invalid_token", status: http.StatusUnauthorized}
)

// Error implements error.
func (e *Error) Error() string {
	if e.Description != "" {
		return fmt.Sprintf("oauth2: %s: %s", e.Code, e.Description)
	}
	return "oauth2: " + e.Code
}

// Unwrap returns the underlying cause, if one was attached.
func (e *Error) Unwrap() error { return e.cause }

// Is reports whether target is an *Error with the same code, so that
// errors.Is(err, oauth2.ErrInvalidGrant) matches a copy carrying a description.
func (e *Error) Is(target error) bool {
	var other *Error
	if !errors.As(target, &other) {
		return false
	}
	return e.Code == other.Code
}

// StatusCode returns the HTTP status this error maps to.
func (e *Error) StatusCode() int {
	if e.status == 0 {
		return http.StatusBadRequest
	}
	return e.status
}

// WithDescription returns a copy of e carrying a client-visible description.
//
// The description crosses the network to a potentially untrusted client, so it
// must stay generic: use it to say what was wrong with the request shape, never
// to reveal whether a client, user, or token exists.
//
// The text is used verbatim. Use [Error.WithDescriptionf] to interpolate.
func (e *Error) WithDescription(description string) *Error {
	c := *e
	c.Description = description
	return &c
}

// WithDescriptionf is [Error.WithDescription] with format interpolation.
//
// Never interpolate attacker-controlled input into a description that is
// returned to the client.
func (e *Error) WithDescriptionf(format string, args ...any) *Error {
	c := *e
	c.Description = fmt.Sprintf(format, args...)
	return &c
}

// WithCause returns a copy of e wrapping err.
//
// The cause is available to the server through errors.Is and errors.As, and is
// never serialized to the client.
func (e *Error) WithCause(err error) *Error {
	c := *e
	c.cause = err
	return &c
}

// WithState returns a copy of e echoing the request's state parameter.
func (e *Error) WithState(state string) *Error {
	c := *e
	c.State = state
	return &c
}

// WithURI returns a copy of e pointing at documentation.
func (e *Error) WithURI(uri string) *Error {
	c := *e
	c.URI = uri
	return &c
}
