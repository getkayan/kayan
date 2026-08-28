package oauth2

import (
	"strconv"
	"time"
)

// AuthenticationRequirements are the authentication constraints an
// authorization request placed on the sign-in (OIDC Core, section 3.1.2.1).
//
// They are carried on [AuthorizeRequest] and on the [AuthCode] it produces,
// because the token endpoint has to know what the authorization endpoint was
// asked for. A constraint that does not survive the code exchange cannot be
// checked when the ID token is minted, which is where checking it matters.
type AuthenticationRequirements struct {
	// MaxAge is the maximum age, in seconds, of the end user's authentication
	// that the relying party will accept. Nil means the parameter was absent.
	//
	// A pointer rather than an int because zero is meaningful: max_age=0 asks
	// the provider to reauthenticate now, and an int could not tell that apart
	// from "not requested".
	MaxAge *int

	// ACRValues lists requested authentication context class references, most
	// preferred first.
	//
	// Unlike SAML's RequestedAuthnContext, OIDC makes acr_values a voluntary
	// request: a provider is permitted to authenticate differently and say so
	// in the acr claim. So this is carried through and reported rather than
	// enforced, and it is the deployment's authentication logic that decides
	// what to do with it.
	ACRValues []string
}

// Requested reports whether the request placed any constraint.
func (r AuthenticationRequirements) Requested() bool {
	return r.MaxAge != nil || len(r.ACRValues) > 0
}

// NeedsReauthentication reports whether an existing session is too old to
// satisfy max_age.
//
// Call it before reusing a session for an authorization request. lastAuth is
// when the end user actually authenticated; a zero value means the deployment
// does not know, which is treated as needing reauthentication -- the request
// asked a question about authentication age, and "unknown" is not an answer
// that satisfies it.
//
//	if req.NeedsReauthentication(session.AuthenticatedAt, time.Now()) {
//	    // show the login page rather than reusing the session
//	}
func (r AuthenticationRequirements) NeedsReauthentication(lastAuth, now time.Time) bool {
	if r.MaxAge == nil {
		return false
	}
	if lastAuth.IsZero() {
		return true
	}
	return now.Sub(lastAuth) > time.Duration(*r.MaxAge)*time.Second
}

// SatisfiedBy reports whether an authentication at lastAuth satisfies max_age.
//
// It is the inverse of [AuthenticationRequirements.NeedsReauthentication] and
// exists because the ID token path reads more naturally as a positive check.
func (r AuthenticationRequirements) SatisfiedBy(lastAuth, now time.Time) bool {
	return !r.NeedsReauthentication(lastAuth, now)
}

// parseMaxAge reads the max_age parameter.
//
// A malformed value is an error rather than an ignored parameter. Dropping it
// would turn "reauthenticate if the session is older than five minutes" into
// "reuse whatever session exists", which is the failure the parameter exists
// to prevent and is invisible to the relying party that sent it.
func parseMaxAge(raw string) (*int, error) {
	if raw == "" {
		return nil, nil
	}
	seconds, err := strconv.Atoi(raw)
	if err != nil || seconds < 0 {
		return nil, ErrInvalidRequest.WithDescription("max_age must be a non-negative number of seconds")
	}
	return &seconds, nil
}
