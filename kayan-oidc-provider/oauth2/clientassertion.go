package oauth2

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/getkayan/kayan/core/keys"
	"github.com/golang-jwt/jwt/v5"
)

// AuthMethodPrivateKeyJWT authenticates the client with a JWT it signed with
// its own private key (RFC 7523 section 2.2, OpenID Connect Core section 9).
//
// It is the method enterprise deployments require, because unlike a shared
// secret the credential never leaves the client: the provider stores only the
// public half, so a compromised provider database cannot be used to
// impersonate the client.
//
// client_secret_jwt, the symmetric sibling, is deliberately absent. Signing an
// assertion with the client secret requires the provider to hold that secret
// in a recoverable form, and Kayan stores only a one-way hash. Supporting it
// would mean storing client secrets reversibly for every deployment,
// including the ones that never use it.
const AuthMethodPrivateKeyJWT = "private_key_jwt"

// ClientAssertionTypeJWTBearer is the only client_assertion_type accepted
// (RFC 7523 section 2.2).
//
// #nosec G101 -- a protocol identifier naming the assertion format, not a credential.
const ClientAssertionTypeJWTBearer = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"

// Errors reported while authenticating a client assertion.
//
// The token endpoint returns invalid_client for all of them; these exist so a
// caller's logs can tell a replay from a bad signature.
var (
	// ErrAssertionReplayed reports a jti that was already used.
	ErrAssertionReplayed = errors.New("oauth2: client assertion jti has already been used")

	// ErrNoAssertionStore reports that private_key_jwt is unusable because no
	// replay store was configured.
	ErrNoAssertionStore = errors.New("oauth2: private_key_jwt requires a client assertion store")
)

// ClientAssertionStore records the assertion identifiers that have been spent.
//
// Without it an assertion is a bearer credential: anyone who observes one --
// a proxy, a log, a mirrored TLS session -- can present it again until it
// expires, and the whole point of private_key_jwt is that possession of the
// key, not of a message, is what authenticates.
//
// Check-and-record is one method on purpose. Two callers presenting the same
// captured assertion concurrently must not both succeed, and an interface
// offering a separate "was it used?" would make that race the caller's to
// notice. Implementations must be atomic: an INSERT on a unique key, or
// Redis SET NX.
type ClientAssertionStore interface {
	// ConsumeAssertionID records jti as spent for clientID, or returns
	// [ErrAssertionReplayed] if it was already recorded.
	//
	// expiresAt is the assertion's own exp. Nothing needs to be kept past it,
	// since an expired assertion is refused before it reaches this call.
	ConsumeAssertionID(ctx context.Context, clientID, jti string, expiresAt time.Time) error
}

// ClientKeyResolver supplies a client's public keys.
//
// Implement it to serve a registered jwks_uri: Kayan never makes outbound HTTP
// requests, so fetching, caching, and refreshing that document belongs to the
// application, along with the decision of how long a cached key set stays good
// after a rotation.
//
// Without one, keys come from [Client.JWKS].
type ClientKeyResolver interface {
	// ClientKeys returns the key set registered for client.
	ClientKeys(ctx context.Context, client *Client) (keys.JWKS, error)
}

// MemoryClientAssertionStore is a single-process [ClientAssertionStore].
//
// It exists so private_key_jwt can be tried without standing up shared
// storage, and it is wrong for more than one process: two replicas keep
// separate sets, so an assertion spent on one is still fresh on the other.
// Any deployment behind a load balancer needs a shared store.
type MemoryClientAssertionStore struct {
	mu   sync.Mutex
	seen map[string]time.Time
}

// NewMemoryClientAssertionStore creates an empty store.
func NewMemoryClientAssertionStore() *MemoryClientAssertionStore {
	return &MemoryClientAssertionStore{seen: map[string]time.Time{}}
}

// ConsumeAssertionID records jti, or reports that it was already spent.
func (s *MemoryClientAssertionStore) ConsumeAssertionID(_ context.Context, clientID, jti string, expiresAt time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now()
	// Drop what has expired. Without this the map grows for the lifetime of
	// the process, one entry per token request.
	for key, exp := range s.seen {
		if now.After(exp) {
			delete(s.seen, key)
		}
	}

	// The client id is part of the key so one client cannot spend another's
	// identifiers, which would be a denial of service against any client whose
	// jti scheme is predictable.
	key := clientID + "\x00" + jti
	if _, used := s.seen[key]; used {
		return ErrAssertionReplayed
	}
	s.seen[key] = expiresAt
	return nil
}

// staticKeyResolver reads keys from Client.JWKS.
type staticKeyResolver struct{}

func (staticKeyResolver) ClientKeys(_ context.Context, client *Client) (keys.JWKS, error) {
	if len(client.JWKS) == 0 {
		return keys.JWKS{}, fmt.Errorf("oauth2: client %q has no registered JWKS", client.ID)
	}
	return keys.ParseJWKS(client.JWKS)
}

// WithClientAssertions enables private_key_jwt.
//
// store records spent assertion identifiers; pass
// [NewMemoryClientAssertionStore] for a single-process deployment. Leaving it
// unset disables the method rather than enabling it without replay protection,
// because an assertion that can be replayed is a bearer token and defeats the
// reason to use asymmetric client authentication at all.
func WithClientAssertions(store ClientAssertionStore) ProviderOption {
	return func(p *Provider) { p.assertionStore = store }
}

// WithClientKeyResolver supplies client public keys from somewhere other than
// [Client.JWKS] -- typically a fetched and cached jwks_uri.
func WithClientKeyResolver(r ClientKeyResolver) ProviderOption {
	return func(p *Provider) { p.clientKeys = r }
}

// WithTokenEndpointURL declares this provider's token endpoint.
//
// It is accepted as a client assertion audience alongside the issuer. RFC 7523
// section 3 allows either, and relying parties disagree about which to send,
// so a deployment that omits this will reject assertions from clients that
// address the endpoint rather than the issuer.
func WithTokenEndpointURL(url string) ProviderOption {
	return func(p *Provider) { p.tokenEndpointURL = url }
}

// WithMaxClientAssertionLifetime bounds how far ahead a client assertion may
// expire. Defaults to one hour.
//
// The bound is what keeps the replay store finite: an assertion with a
// ten-year exp would occupy an entry for ten years, and a client that issues
// them in a loop turns that into unbounded growth in shared storage.
func WithMaxClientAssertionLifetime(d time.Duration) ProviderOption {
	return func(p *Provider) { p.maxAssertionLifetime = d }
}

// defaultMaxAssertionLifetime bounds an assertion's exp when none is set.
const defaultMaxAssertionLifetime = time.Hour

// assertionClockSkew tolerates disagreement between the client's clock and
// this provider's on nbf. exp is deliberately not extended: accepting an
// expired assertion widens the replay window at the moment the store is about
// to forget it.
const assertionClockSkew = 2 * time.Minute

// assertionAlgorithms are the signature algorithms a client assertion may use.
//
// The list is asymmetric-only and explicit. The parser must be given one, or a
// token whose header says "alg": "none" parses as valid, and one saying HS256
// is verified against whatever the key resolver returned -- which for a public
// key is the algorithm-confusion attack, since a client's public key is not a
// secret.
var assertionAlgorithms = []string{
	"RS256", "RS384", "RS512",
	"PS256", "PS384", "PS512",
	"ES256", "ES384", "ES512",
	"EdDSA",
}

// authenticateAssertion authenticates a client from a client_assertion.
//
// The order of checks matters. Everything that does not need the signature is
// verified before it, so a malformed assertion costs no asymmetric operation,
// and nothing read before the signature check is used for a decision.
func (p *Provider) authenticateAssertion(ctx context.Context, formClientID, assertionType, assertion string) (*Client, error) {
	if assertionType != ClientAssertionTypeJWTBearer {
		return nil, ErrInvalidClient.WithDescription("unsupported client_assertion_type")
	}
	if p.assertionStore == nil {
		// Fail closed. Accepting the assertion without a replay store would
		// silently downgrade private_key_jwt to a bearer credential.
		return nil, ErrInvalidClient.WithDescription("client authentication failed").
			WithCause(ErrNoAssertionStore)
	}

	// The claims are read twice: once unverified, only to learn which client
	// to look up, and again below from the verified token. Nothing from this
	// first pass survives into a decision.
	unverified := jwt.MapClaims{}
	parser := jwt.NewParser(jwt.WithValidMethods(assertionAlgorithms))
	if _, _, err := parser.ParseUnverified(assertion, unverified); err != nil {
		return nil, ErrInvalidClient.WithDescription("malformed client_assertion").WithCause(err)
	}
	issuer, _ := unverified["iss"].(string)
	if issuer == "" {
		return nil, ErrInvalidClient.WithDescription("client_assertion has no iss")
	}
	// A client_id sent alongside the assertion must agree with it. Letting the
	// two differ means the request is authenticated as one client and
	// attributed to another.
	if formClientID != "" && formClientID != issuer {
		return nil, ErrInvalidClient.WithDescription("client_id does not match the client_assertion issuer")
	}

	client, err := p.clientStore.GetClient(ctx, issuer)
	if err != nil {
		return nil, ErrInvalidClient.WithDescription("client authentication failed").WithCause(err)
	}
	if client == nil {
		return nil, ErrInvalidClient.WithDescription("client authentication failed")
	}
	// A client registered for a shared secret must not authenticate with an
	// assertion. Without this, registering a JWKS on any client would add a
	// second credential nobody configured, while the registration still read
	// as client_secret_basic.
	if client.TokenEndpointAuthMethod != AuthMethodPrivateKeyJWT {
		return nil, ErrInvalidClient.WithDescription("client authentication failed")
	}

	set, err := p.clientKeyResolver().ClientKeys(ctx, client)
	if err != nil {
		return nil, ErrInvalidClient.WithDescription("client authentication failed").WithCause(err)
	}

	claims := jwt.MapClaims{}
	token, err := jwt.ParseWithClaims(assertion, claims, func(t *jwt.Token) (any, error) {
		kid, _ := t.Header["kid"].(string)
		jwk, found := set.Find(kid)
		if !found {
			return nil, fmt.Errorf("no registered key for kid %q", kid)
		}
		return jwk.PublicKey()
	},
		jwt.WithValidMethods(assertionAlgorithms),
		jwt.WithLeeway(assertionClockSkew),
		// Every claim is checked below instead. The library's audience check
		// passes when aud is absent and its expiry check passes when exp is
		// absent; both are required here, and both are the checks that stop an
		// assertion minted elsewhere from working.
		jwt.WithoutClaimsValidation(),
	)
	if err != nil || token == nil || !token.Valid {
		return nil, ErrInvalidClient.WithDescription("client authentication failed").WithCause(err)
	}

	if err := p.validateAssertionClaims(ctx, client, claims); err != nil {
		return nil, err
	}
	return client, nil
}

// validateAssertionClaims checks the claims of an assertion whose signature
// has already been verified.
func (p *Provider) validateAssertionClaims(ctx context.Context, client *Client, claims jwt.MapClaims) error {
	// RFC 7523 section 3: iss and sub are both the client id. sub names the
	// authenticating party, so a mismatch means the client signed an assertion
	// about somebody else.
	if iss, _ := claims["iss"].(string); iss != client.ID {
		return ErrInvalidClient.WithDescription("client authentication failed")
	}
	if sub, _ := claims["sub"].(string); sub != client.ID {
		return ErrInvalidClient.WithDescription("client_assertion sub must be the client id")
	}

	// The audience is what stops an assertion minted for another provider from
	// being presented here. A relying party that talks to several providers
	// hands each one a credential signed by the same key; without this check
	// any of them could replay it against the others.
	if !p.assertionAudienceMatches(claims) {
		return ErrInvalidClient.WithDescription("client_assertion audience is not this provider")
	}

	expiry, ok := claimTime(claims, "exp")
	if !ok {
		return ErrInvalidClient.WithDescription("client_assertion has no exp")
	}
	now := p.clock.Now()
	if !expiry.After(now) {
		return ErrInvalidClient.WithDescription("client_assertion has expired")
	}
	// An unbounded exp would hold a replay-store entry for as long as it
	// claims, which is how a client turns shared storage into a growth
	// problem.
	if limit := p.assertionLifetimeLimit(); expiry.After(now.Add(limit)) {
		return ErrInvalidClient.WithDescriptionf("client_assertion expires more than %s ahead", limit)
	}
	if notBefore, present := claimTime(claims, "nbf"); present && notBefore.After(now.Add(assertionClockSkew)) {
		return ErrInvalidClient.WithDescription("client_assertion is not yet valid")
	}

	// jti last, so an assertion rejected for any other reason is not spent.
	// Consuming first would let an attacker burn a legitimate client's
	// identifiers by replaying captured assertions with a broken audience.
	jti, _ := claims["jti"].(string)
	if jti == "" {
		return ErrInvalidClient.WithDescription("client_assertion has no jti")
	}
	if err := p.assertionStore.ConsumeAssertionID(ctx, client.ID, jti, expiry); err != nil {
		return ErrInvalidClient.WithDescription("client authentication failed").WithCause(err)
	}
	return nil
}

// assertionAudienceMatches reports whether aud names this provider.
//
// aud is a string or an array of them (RFC 7519 section 4.1.3), and either the
// issuer identifier or the token endpoint URL is acceptable (RFC 7523
// section 3). Relying parties disagree about which to send.
func (p *Provider) assertionAudienceMatches(claims jwt.MapClaims) bool {
	accepted := func(value string) bool {
		if value == "" {
			return false
		}
		return value == p.issuer || (p.tokenEndpointURL != "" && value == p.tokenEndpointURL)
	}

	switch aud := claims["aud"].(type) {
	case string:
		return accepted(aud)
	case []any:
		for _, entry := range aud {
			if s, ok := entry.(string); ok && accepted(s) {
				return true
			}
		}
	case []string:
		for _, entry := range aud {
			if accepted(entry) {
				return true
			}
		}
	}
	// An absent or unrecognisably shaped aud is a miss. Treating it as a match
	// would accept an assertion minted for any provider at all.
	return false
}

// clientKeyResolver returns the configured resolver, or the one that reads
// Client.JWKS.
func (p *Provider) clientKeyResolver() ClientKeyResolver {
	if p.clientKeys != nil {
		return p.clientKeys
	}
	return staticKeyResolver{}
}

// assertionLifetimeLimit returns the configured bound on exp.
func (p *Provider) assertionLifetimeLimit() time.Duration {
	if p.maxAssertionLifetime > 0 {
		return p.maxAssertionLifetime
	}
	return defaultMaxAssertionLifetime
}

// claimTime reads a numeric date claim (RFC 7519 section 2).
func claimTime(claims jwt.MapClaims, name string) (time.Time, bool) {
	switch value := claims[name].(type) {
	case float64:
		return time.Unix(int64(value), 0), true
	case int64:
		return time.Unix(value, 0), true
	case json.Number:
		seconds, err := value.Int64()
		if err != nil {
			return time.Time{}, false
		}
		return time.Unix(seconds, 0), true
	}
	return time.Time{}, false
}
