package oauth2

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"sync"
	"time"
)

// RequestURIPrefix is the URN scheme a pushed authorization request is
// addressed by (RFC 9126 section 2.2).
const RequestURIPrefix = "urn:ietf:params:oauth:request_uri:"

// DefaultPushedRequestTTL is how long a pushed request may be redeemed for.
//
// RFC 9126 section 2.2 recommends a value between five seconds and ten
// minutes. Short is the point: the request_uri is a bearer reference to a
// fully validated authorization request, so its lifetime is the window in
// which a leaked one is useful.
const DefaultPushedRequestTTL = 60 * time.Second

// Errors reported by the pushed authorization request endpoint.
var (
	// ErrNoPushedRequestStore reports that PAR is unusable because no store
	// was configured.
	ErrNoPushedRequestStore = errors.New("oauth2: pushed authorization requests require a store")

	// ErrPushedRequestNotFound reports a request_uri that is unknown, expired,
	// or already redeemed.
	//
	// The three are one error on purpose. Distinguishing them tells an
	// attacker holding a captured request_uri whether it was ever valid.
	ErrPushedRequestNotFound = errors.New("oauth2: unknown or expired request_uri")
)

// PushedRequest is an authorization request a client lodged in advance.
type PushedRequest struct {
	// URI is the request_uri handed back to the client, in URN form.
	URI string

	// ClientID is the client that pushed it. The authorization request that
	// redeems the URI must name the same client.
	ClientID string

	// Parameters are the authorization request parameters exactly as pushed.
	Parameters url.Values

	// ExpiresAt is when the URI stops being redeemable.
	ExpiresAt time.Time
}

// PushedRequestStore persists pushed authorization requests.
//
// Consume is a single method for the same reason the client assertion store's
// is: a request_uri is one-time use (RFC 9126 section 6), and an interface
// that let a caller read then delete would put the race in every
// implementation. Two authorization requests redeeming one URI concurrently
// must not both succeed.
type PushedRequestStore interface {
	// SavePushedRequest stores a pushed request.
	SavePushedRequest(ctx context.Context, request *PushedRequest) error

	// ConsumePushedRequest returns the request for uri and removes it, or
	// returns [ErrPushedRequestNotFound] if it is unknown, expired, or has
	// already been redeemed.
	ConsumePushedRequest(ctx context.Context, uri string) (*PushedRequest, error)
}

// MemoryPushedRequestStore is a single-process [PushedRequestStore].
//
// It is wrong for more than one process: a request pushed to one replica
// cannot be redeemed on another, so the authorization request fails roughly
// (replicas - 1) times out of replicas. Any deployment behind a load balancer
// needs a shared store.
type MemoryPushedRequestStore struct {
	mu       sync.Mutex
	requests map[string]*PushedRequest
}

// NewMemoryPushedRequestStore creates an empty store.
func NewMemoryPushedRequestStore() *MemoryPushedRequestStore {
	return &MemoryPushedRequestStore{requests: map[string]*PushedRequest{}}
}

// SavePushedRequest stores a pushed request.
func (s *MemoryPushedRequestStore) SavePushedRequest(_ context.Context, request *PushedRequest) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now()
	for uri, stored := range s.requests {
		if now.After(stored.ExpiresAt) {
			delete(s.requests, uri)
		}
	}

	s.requests[request.URI] = request
	return nil
}

// ConsumePushedRequest returns and removes a pushed request.
func (s *MemoryPushedRequestStore) ConsumePushedRequest(_ context.Context, uri string) (*PushedRequest, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	request, ok := s.requests[uri]
	if !ok {
		return nil, ErrPushedRequestNotFound
	}
	// Removed whether or not it is still valid. An expired entry left in place
	// is a leak, and returning it would be worse.
	delete(s.requests, uri)

	if time.Now().After(request.ExpiresAt) {
		return nil, ErrPushedRequestNotFound
	}
	return request, nil
}

// WithPushedRequests enables the pushed authorization request endpoint
// (RFC 9126).
//
// PAR moves the authorization request off the browser's URL bar and into a
// direct, client-authenticated call. What that buys is integrity: the
// parameters cannot be inspected, reordered, or altered between the client and
// this provider, which is why it is required by FAPI and by every profile that
// takes request tampering seriously.
//
// Leaving the store unset disables the endpoint rather than serving it without
// persistence.
func WithPushedRequests(store PushedRequestStore) ProviderOption {
	return func(p *Provider) { p.pushedRequests = store }
}

// WithPushedRequestTTL sets how long a request_uri may be redeemed for.
// Defaults to [DefaultPushedRequestTTL].
func WithPushedRequestTTL(d time.Duration) ProviderOption {
	return func(p *Provider) { p.pushedRequestTTL = d }
}

// WithRequirePushedRequests refuses any authorization request that did not
// arrive through the PAR endpoint.
//
// FAPI 2.0 requires this. Without it a client may still send a plain
// authorization request, so the integrity PAR provides is available rather
// than enforced -- and an attacker who can influence a redirect will simply
// use the path that has no integrity.
func WithRequirePushedRequests(required bool) ProviderOption {
	return func(p *Provider) { p.requirePAR = required }
}

// SupportsPushedRequests reports whether the PAR endpoint is usable.
func (p *Provider) SupportsPushedRequests() bool { return p.pushedRequests != nil }

// RequiresPushedRequests reports whether plain authorization requests are
// refused.
func (p *Provider) RequiresPushedRequests() bool { return p.requirePAR }

// PushAuthorizationRequest handles the pushed authorization request endpoint
// (RFC 9126 section 2).
//
// It authenticates the client exactly as the token endpoint does -- including
// private_key_jwt -- validates the authorization request in full, and returns
// a request_uri the client passes to the authorization endpoint in place of
// the parameters.
//
// Validating here rather than at redemption is deliberate: an invalid request
// is reported to the client over a direct, authenticated channel where it can
// be read, instead of becoming a redirect the end user sees.
func (p *Provider) PushAuthorizationRequest(ctx context.Context, values url.Values, authorization string) (*PushedRequest, error) {
	if p.pushedRequests == nil {
		return nil, ErrInvalidRequest.WithDescription("pushed authorization requests are not enabled").
			WithCause(ErrNoPushedRequestStore)
	}

	// RFC 9126 section 2.1: a request_uri parameter is not allowed here.
	// Accepting one would let a client chain a pushed request into another,
	// and the second would inherit the first's already-validated parameters
	// while presenting its own client authentication.
	if values.Get("request_uri") != "" {
		return nil, ErrInvalidRequest.WithDescription("request_uri is not allowed at the pushed authorization request endpoint")
	}

	creds, err := clientCredentials(values, authorization)
	if err != nil {
		return nil, err
	}
	client, err := p.authenticateWith(ctx, creds, GrantAuthorizationCode)
	if err != nil {
		return nil, err
	}

	// A client_id that disagrees with the authenticated client would have the
	// request validated against one registration and redeemed as another.
	if id := values.Get("client_id"); id != "" && id != client.ID {
		return nil, ErrInvalidRequest.WithDescription("client_id does not match the authenticated client")
	}

	// Parsed with client_id filled in from the authentication, so the checks
	// run against the client that actually pushed this.
	parameters := cloneValues(values)
	parameters.Set("client_id", client.ID)
	// Client credentials have no place in a stored authorization request.
	// Leaving them would persist a secret, and re-present it at redemption
	// where nothing authenticates.
	for _, name := range []string{"client_secret", "client_assertion", "client_assertion_type"} {
		parameters.Del(name)
	}

	if _, err := p.parseAuthorizeParameters(ctx, parameters); err != nil {
		return nil, err
	}

	uri, err := p.tokens()
	if err != nil {
		return nil, ErrServerError.WithCause(err)
	}

	request := &PushedRequest{
		URI:        RequestURIPrefix + uri,
		ClientID:   client.ID,
		Parameters: parameters,
		ExpiresAt:  p.clock.Now().Add(p.pushedRequestLifetime()),
	}
	if err := p.pushedRequests.SavePushedRequest(ctx, request); err != nil {
		return nil, ErrServerError.WithCause(err)
	}
	return request, nil
}

// ExpiresIn returns the seconds remaining, for the endpoint's JSON response.
func (r *PushedRequest) ExpiresIn(now time.Time) int64 {
	remaining := int64(r.ExpiresAt.Sub(now).Seconds())
	if remaining < 0 {
		return 0
	}
	return remaining
}

// resolvePushedRequest replaces an authorization request carrying a
// request_uri with the parameters that were pushed.
//
// The pushed parameters are used alone. RFC 9126 section 4 requires it, and
// the reason is direct: merging in whatever else arrived on the authorization
// URL would let anyone holding a victim's request_uri append their own
// redirect_uri and receive the code. The whole value of PAR is that the
// parameters were fixed at push time.
func (p *Provider) resolvePushedRequest(ctx context.Context, values url.Values) (url.Values, error) {
	uri := values.Get("request_uri")
	if uri == "" {
		if p.requirePAR {
			return nil, ErrInvalidRequest.WithDescription("this provider requires a pushed authorization request")
		}
		return values, nil
	}
	if p.pushedRequests == nil {
		return nil, ErrInvalidRequest.WithDescription("pushed authorization requests are not enabled")
	}
	if !strings.HasPrefix(uri, RequestURIPrefix) {
		// Only the URN form is accepted. A request_uri that is a URL is the
		// RFC 9101 fetch-the-request-object feature, which this provider does
		// not implement -- and treating an arbitrary URL as one would make the
		// authorization endpoint fetch attacker-chosen addresses.
		return nil, ErrInvalidRequest.WithDescription("request_uri must be a pushed authorization request URN")
	}

	request, err := p.pushedRequests.ConsumePushedRequest(ctx, uri)
	if err != nil {
		return nil, ErrInvalidRequest.WithDescription("unknown or expired request_uri").WithCause(err)
	}
	if !p.clock.Now().Before(request.ExpiresAt) {
		return nil, ErrInvalidRequest.WithDescription("unknown or expired request_uri").
			WithCause(ErrPushedRequestNotFound)
	}

	// The client_id on the authorization URL is the one parameter that may
	// appear alongside request_uri (RFC 9126 section 4). It has to match: a
	// captured request_uri redeemed under another client would run one
	// client's validated request against another's registration.
	if id := values.Get("client_id"); id != "" && id != request.ClientID {
		return nil, ErrInvalidRequest.WithDescription("client_id does not match the pushed request")
	}

	return cloneValues(request.Parameters), nil
}

// pushedRequestLifetime returns the configured request_uri lifetime.
func (p *Provider) pushedRequestLifetime() time.Duration {
	if p.pushedRequestTTL > 0 {
		return p.pushedRequestTTL
	}
	return DefaultPushedRequestTTL
}

// cloneValues copies a url.Values so a stored request cannot be mutated
// through a slice the caller still holds.
func cloneValues(values url.Values) url.Values {
	out := make(url.Values, len(values))
	for name, entries := range values {
		out[name] = append([]string(nil), entries...)
	}
	return out
}

// pushedRequestJSON is the endpoint's response body (RFC 9126 section 2.2).
//
// It is here rather than left to the caller because the field names are part
// of the protocol, and a caller assembling them by hand is a caller who can
// get expires_in wrong in a way nothing detects until a client's clock
// disagrees.
type pushedRequestJSON struct {
	RequestURI string `json:"request_uri"`
	ExpiresIn  int64  `json:"expires_in"`
}

// Response returns the endpoint's JSON body for this pushed request.
func (r *PushedRequest) Response(now time.Time) any {
	return pushedRequestJSON{RequestURI: r.URI, ExpiresIn: r.ExpiresIn(now)}
}

// String renders the request for logs without its parameters, which carry
// state and PKCE values.
func (r *PushedRequest) String() string {
	return fmt.Sprintf("PushedRequest{client=%s expires=%s}", r.ClientID, r.ExpiresAt.UTC().Format(time.RFC3339))
}
