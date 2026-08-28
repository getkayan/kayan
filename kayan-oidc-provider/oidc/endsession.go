package oidc

import (
	"context"
	"crypto/ecdsa"
	"crypto/rsa"
	"errors"
	"fmt"
	"net/url"

	"github.com/getkayan/kayan/kayan-oidc-provider/oauth2"
	"github.com/golang-jwt/jwt/v5"
)

// Errors returned by [Server.ParseEndSessionRequest].
var (
	// ErrNoClientStore reports that logout cannot be served because no client
	// store is configured. Without one there is no allowlist to validate a
	// post_logout_redirect_uri against.
	ErrNoClientStore = errors.New("oidc: RP-initiated logout requires a client store")

	// ErrInvalidIDTokenHint reports an id_token_hint that is absent where
	// required, malformed, or not signed by this provider.
	ErrInvalidIDTokenHint = errors.New("oidc: invalid id_token_hint")

	// ErrUnknownClient reports that the request named a client this provider
	// does not know.
	ErrUnknownClient = errors.New("oidc: unknown client")

	// ErrPostLogoutRedirectNotRegistered reports a post_logout_redirect_uri
	// that is not on the identified client's allowlist.
	ErrPostLogoutRedirectNotRegistered = errors.New("oidc: post_logout_redirect_uri is not registered for this client")
)

// WithClientStore supplies the client store RP-initiated logout validates
// against.
//
// Without it [Server.ParseEndSessionRequest] refuses every request carrying a
// post_logout_redirect_uri, and [BuildDiscovery] refuses to advertise an
// end-session endpoint the provider cannot serve.
func WithClientStore(cs oauth2.ClientStore) ServerOption {
	return func(s *Server) { s.clients = cs }
}

// EndSessionRequest is a validated RP-initiated logout request
// (OpenID Connect RP-Initiated Logout 1.0, section 2).
type EndSessionRequest struct {
	// ClientID is the client the request was attributed to, established from a
	// verified id_token_hint or from an explicit client_id. Empty when the
	// request named neither.
	ClientID string

	// Subject is the end user named by a verified id_token_hint, empty
	// otherwise.
	Subject string

	// SessionID is the sid claim of a verified id_token_hint, empty otherwise.
	// It names which session to end when the subject has several.
	SessionID string

	// PostLogoutRedirectURI is where to send the user afterwards. It is
	// populated only after being matched against the identified client's
	// registered allowlist, so a non-empty value here has been validated.
	PostLogoutRedirectURI string

	// State is the client's opaque value, returned on the redirect.
	State string

	// LogoutHint is the raw logout_hint parameter.
	//
	// It is unauthenticated text supplied by whoever built the URL, and the
	// specification's intent is that it hints which user to sign out. Treat it
	// as a display or lookup hint only: selecting a session from it hands any
	// caller a cross-user logout primitive, and rendering it into the
	// confirmation page without escaping is an injection into the one page
	// this flow asks the caller to build.
	LogoutHint string

	// ConfirmationRequired reports whether the caller should ask the user to
	// confirm before ending the session.
	//
	// It is false only when a verified id_token_hint identified both the
	// subject and the session, which is the case where the request
	// demonstrably came from a party already holding a token for that exact
	// session. Anything less -- no hint, or a hint naming a different session
	// -- means the request could have been made by a third party, and the
	// specification requires confirmation.
	ConfirmationRequired bool
}

// RedirectURL returns the URL to send the user to after the session ends.
//
// It returns an empty string when the request carried no validated redirect
// target, in which case the caller renders its own logged-out page.
//
// Any query the registered URI already carries is preserved: relying parties
// do register URIs with parameters, and replacing the query would break them.
// state is appended only when the request supplied one, since the
// specification returns it only if it was sent.
func (r *EndSessionRequest) RedirectURL() string {
	if r.PostLogoutRedirectURI == "" {
		return ""
	}
	if r.State == "" {
		return r.PostLogoutRedirectURI
	}

	parsed, err := url.Parse(r.PostLogoutRedirectURI)
	if err != nil {
		// Unreachable in practice: the URI came from a registered allowlist and
		// was parsed during validation. Returning it unchanged is safer than
		// returning a string this function assembled from a failed parse.
		return r.PostLogoutRedirectURI
	}
	query := parsed.Query()
	query.Set("state", r.State)
	parsed.RawQuery = query.Encode()
	return parsed.String()
}

// ParseEndSessionRequest validates an RP-initiated logout request.
//
// It is the end-session endpoint's logic without the transport: the caller
// hands over the query, ends the session itself, and redirects to
// [EndSessionRequest.RedirectURL].
//
// The security of this endpoint is the redirect allowlist. Discovery
// advertises an end_session_endpoint, and an unvalidated
// post_logout_redirect_uri makes it an open redirector on an authentication
// domain -- a phishing primitive that inherits the provider's reputation.
// A redirect target is therefore returned only after the request has been
// attributed to a client and matched against that client's registered
// allowlist.
//
// A present but unverifiable id_token_hint is an error. Falling back to the
// client_id parameter would let an attacker send a deliberately broken hint
// alongside any client_id they like and have the request validated against
// that client's allowlist instead -- the downgrade is more useful to an
// attacker than no hint at all.
func (s *Server) ParseEndSessionRequest(ctx context.Context, values url.Values) (*EndSessionRequest, error) {
	req := &EndSessionRequest{
		State:      values.Get("state"),
		LogoutHint: values.Get("logout_hint"),
		// Confirmation is required until a verified hint proves otherwise.
		ConfirmationRequired: true,
	}

	redirectURI := values.Get("post_logout_redirect_uri")

	// Resolved from the hint first, because a hint that fails to verify must
	// stop the request rather than fall through to the client_id below.
	if hint := values.Get("id_token_hint"); hint != "" {
		claims, err := s.verifyIDTokenHint(ctx, hint)
		if err != nil {
			return nil, err
		}
		req.ClientID = claimAsString(claims, "aud")
		req.Subject = claimAsString(claims, "sub")
		req.SessionID = claimAsString(claims, "sid")

		// A hint identifying the exact session is what makes confirmation
		// unnecessary. Matching only the subject would let a token minted for
		// one device silently end another.
		req.ConfirmationRequired = req.SessionID == ""
	} else if clientID := values.Get("client_id"); clientID != "" {
		req.ClientID = clientID
	}

	if redirectURI == "" {
		return req, nil
	}

	// Everything below needs the client store. The guard precedes any use of
	// it: calling a method on a nil interface would panic inside a parser
	// reachable from any query string.
	if s.clients == nil {
		return nil, ErrNoClientStore
	}
	if req.ClientID == "" {
		return nil, fmt.Errorf("%w: a post_logout_redirect_uri requires an id_token_hint or a client_id "+
			"to identify whose allowlist to check", ErrUnknownClient)
	}

	client, err := s.clients.GetClient(ctx, req.ClientID)
	if err != nil {
		return nil, fmt.Errorf("oidc: resolve client: %w", err)
	}
	// A store may report a miss as (nil, nil); dereferencing that would panic.
	if client == nil {
		return nil, ErrUnknownClient
	}

	if !client.AllowsPostLogoutRedirectURI(redirectURI) {
		return nil, ErrPostLogoutRedirectNotRegistered
	}
	req.PostLogoutRedirectURI = redirectURI

	return req, nil
}

// verifyIDTokenHint checks that a hint is a token this provider signed.
//
// Claims validation is deliberately skipped: an id_token_hint is expected to
// be expired, since the user is signing out of the session it was issued for.
// The signature, the issuer, and the key it was signed with are what make it
// evidence of anything.
func (s *Server) verifyIDTokenHint(ctx context.Context, hint string) (jwt.MapClaims, error) {
	claims := jwt.MapClaims{}

	_, err := jwt.ParseWithClaims(hint, claims, func(t *jwt.Token) (any, error) {
		if s.keyProvider != nil {
			kid, _ := t.Header["kid"].(string)
			if kid == "" {
				// Resolving a kid-less token against the active key would let a
				// token signed by a retired key keep identifying a client after
				// a rotation.
				return nil, fmt.Errorf("%w: token has no kid", ErrInvalidIDTokenHint)
			}
			key, err := s.keyProvider.ByKID(ctx, kid)
			if err != nil {
				return nil, err
			}
			if key.Method.Alg() != t.Method.Alg() {
				return nil, fmt.Errorf("%w: token alg %q does not match key %q",
					ErrInvalidIDTokenHint, t.Method.Alg(), key.Method.Alg())
			}
			return key.Public, nil
		}
		return hintVerificationKey(s.signingKey), nil
	}, jwt.WithoutClaimsValidation())

	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidIDTokenHint, err)
	}

	// A token this provider signed but issued as a different issuer is not
	// evidence about this one. Reachable where a deployment issues under
	// several issuer values from one key, which per-tenant issuers do.
	if iss := claimAsString(claims, "iss"); iss != s.issuer {
		return nil, fmt.Errorf("%w: issued by %q", ErrInvalidIDTokenHint, iss)
	}

	return claims, nil
}

// hintVerificationKey derives the public half of a signing key.
func hintVerificationKey(signingKey any) any {
	switch key := signingKey.(type) {
	case *rsa.PrivateKey:
		return &key.PublicKey
	case *ecdsa.PrivateKey:
		return &key.PublicKey
	default:
		return signingKey
	}
}

// claimAsString reads a string claim, tolerating the single-element array form
// identity providers use for aud.
func claimAsString(claims jwt.MapClaims, name string) string {
	switch value := claims[name].(type) {
	case string:
		return value
	case []any:
		// A multi-valued aud gives no basis for picking one, so none is used
		// rather than silently taking the first.
		if len(value) == 1 {
			if s, ok := value[0].(string); ok {
				return s
			}
		}
	case []string:
		if len(value) == 1 {
			return value[0]
		}
	}
	return ""
}
