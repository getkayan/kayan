package saml

import (
	"encoding/xml"
	"errors"
	"fmt"
	"time"
)

// Errors reported when an identity provider did not honour the authentication
// options a request asked for.
var (
	// ErrAuthnContextNotSatisfied reports an assertion whose authentication
	// context is not one the request asked for.
	//
	// This is the error that makes RequestedAuthnContext worth sending. An
	// identity provider is free to ignore the request and return a
	// password-only assertion to a service provider that asked for
	// multi-factor. If the service provider accepts it, the step-up it
	// performed for a sensitive operation never happened, and every log says
	// it did.
	ErrAuthnContextNotSatisfied = errors.New("saml: assertion does not satisfy the requested authentication context")

	// ErrStaleAuthentication reports an assertion whose AuthnInstant predates
	// the request that asked for a fresh authentication.
	//
	// ForceAuthn asks the identity provider to reauthenticate the user rather
	// than reuse an existing session. An identity provider that ignores it
	// answers from the session it already had, and the only evidence is that
	// the subject authenticated before this request was made.
	ErrStaleAuthentication = errors.New("saml: assertion reports an authentication older than the request that forced one")
)

// Common authentication context class references (SAML 2.0 Authentication
// Context, section 3).
const (
	// AuthnContextPassword is a password over an unprotected transport.
	AuthnContextPassword = "urn:oasis:names:tc:SAML:2.0:ac:classes:Password"

	// AuthnContextPasswordProtectedTransport is a password over TLS. This is
	// what most identity providers assert for an ordinary login.
	AuthnContextPasswordProtectedTransport = "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport"

	// AuthnContextMFA is the multi-factor class. Note that identity providers
	// disagree about which reference they assert for MFA -- Entra ID uses
	// http://schemas.microsoft.com/claims/multipleauthn -- so a deployment
	// usually lists more than one acceptable value.
	AuthnContextMFA = "urn:oasis:names:tc:SAML:2.0:ac:classes:MultiFactor"

	// AuthnContextX509 is a certificate-based authentication.
	AuthnContextX509 = "urn:oasis:names:tc:SAML:2.0:ac:classes:X509"
)

// Comparison values for RequestedAuthnContext (SAML 2.0 Core, section 3.3.2.2.1).
const (
	ComparisonExact   = "exact"
	ComparisonMinimum = "minimum"
	ComparisonBetter  = "better"
	ComparisonMaximum = "maximum"
)

// RequestedAuthnContext asks the identity provider for a particular kind of
// authentication (SAML 2.0 Core, section 3.3.2.2.1).
type RequestedAuthnContext struct {
	XMLName              xml.Name `xml:"urn:oasis:names:tc:SAML:2.0:protocol RequestedAuthnContext"`
	Comparison           string   `xml:"Comparison,attr,omitempty"`
	AuthnContextClassRef []string `xml:"urn:oasis:names:tc:SAML:2.0:assertion AuthnContextClassRef"`
}

// LoginOptions are the per-login authentication options of an AuthnRequest.
//
// They are per login rather than per identity provider because that is how
// they are used: the same identity provider serves an ordinary sign-in and a
// step-up before a sensitive operation, and only the second asks for a fresh
// multi-factor authentication.
type LoginOptions struct {
	// ForceAuthn asks the identity provider to reauthenticate the subject
	// rather than answer from an existing session (SAML 2.0 Core, section
	// 3.4.1).
	//
	// It is checked on the way back: the assertion's AuthnInstant must not
	// predate the request. An identity provider that ignores ForceAuthn is
	// otherwise indistinguishable from one that honoured it.
	ForceAuthn bool

	// IsPassive asks the identity provider not to take visible control of the
	// user interface. Used to test for an existing session without showing a
	// login page; the identity provider answers with a NoPassive status when
	// it cannot comply, which surfaces as a status error.
	IsPassive bool

	// RequestedAuthnContexts lists acceptable authentication context class
	// references. An assertion whose context is not among them is refused with
	// [ErrAuthnContextNotSatisfied].
	//
	// List every reference a deployment considers acceptable. Identity
	// providers disagree about which one they assert for the same
	// authentication, so a single-valued list frequently rejects a login that
	// did satisfy the requirement.
	RequestedAuthnContexts []string

	// Comparison is how the identity provider should interpret the requested
	// contexts. Empty means "exact", which is the specification's default.
	//
	// It affects only what is asked for. The check on the way back is always
	// membership in RequestedAuthnContexts, because a comparison like
	// "minimum" describes an ordering over classes that only the deployment
	// knows -- this library cannot rank an identity provider's proprietary
	// references, and pretending to would let anything through.
	Comparison string

	// RelayState is the opaque value returned with the response.
	RelayState string
}

// requested reports whether any option needs enforcing on the response.
func (o LoginOptions) requested() bool {
	return o.ForceAuthn || len(o.RequestedAuthnContexts) > 0
}

// applyTo writes the options onto an AuthnRequest.
func (o LoginOptions) applyTo(req *AuthnRequest) {
	req.ForceAuthn = o.ForceAuthn
	req.IsPassive = o.IsPassive

	if len(o.RequestedAuthnContexts) > 0 {
		comparison := o.Comparison
		if comparison == "" {
			comparison = ComparisonExact
		}
		req.RequestedAuthnContext = &RequestedAuthnContext{
			Comparison:           comparison,
			AuthnContextClassRef: append([]string(nil), o.RequestedAuthnContexts...),
		}
	}
}

// enforceAuthnOptions checks that the identity provider honoured what the
// request asked for.
//
// It runs on the signature-verified assertion, which is the only place these
// claims mean anything: an AuthnStatement read from an unverified document
// says whatever the sender wanted it to say.
//
// requestedAt is when this service provider issued the request. skew tolerates
// clock disagreement between the two parties.
func enforceAuthnOptions(assertion *Assertion, session *Session, requestedAt time.Time, skew time.Duration) error {
	if session == nil || !session.ForceAuthn && len(session.RequestedAuthnContexts) == 0 {
		return nil
	}

	// An assertion with no AuthnStatement carries no evidence about how the
	// subject authenticated. When nothing was asked for that is acceptable;
	// once something was, its absence is a failure rather than a pass. The
	// alternative reads "we could not tell, so we allowed it".
	if assertion.AuthnStatement == nil {
		return fmt.Errorf("%w: the assertion carries no AuthnStatement",
			ErrAuthnContextNotSatisfied)
	}

	if len(session.RequestedAuthnContexts) > 0 {
		got := ""
		if assertion.AuthnStatement.AuthnContext != nil {
			got = assertion.AuthnStatement.AuthnContext.AuthnContextClassRef
		}
		if !containsString(session.RequestedAuthnContexts, got) {
			return fmt.Errorf("%w: got %q, wanted one of %v",
				ErrAuthnContextNotSatisfied, got, session.RequestedAuthnContexts)
		}
	}

	if session.ForceAuthn {
		instant := assertion.AuthnStatement.AuthnInstant
		if instant.IsZero() {
			return fmt.Errorf("%w: the assertion reports no AuthnInstant",
				ErrStaleAuthentication)
		}
		// The authentication must not predate the request that demanded one.
		// An identity provider answering from a session it already had reports
		// the moment that older session began.
		if instant.Before(requestedAt.Add(-skew)) {
			return fmt.Errorf("%w: authenticated at %s, request issued at %s",
				ErrStaleAuthentication, instant.UTC().Format(time.RFC3339), requestedAt.UTC().Format(time.RFC3339))
		}
	}

	return nil
}

// containsString reports whether value is in list.
func containsString(list []string, value string) bool {
	if value == "" {
		return false
	}
	for _, entry := range list {
		if entry == value {
			return true
		}
	}
	return false
}
