package flow

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"time"

	"github.com/getkayan/kayan/core/identity"
)

// KayanOIDCRepository is the storage contract for the kayan_oidc strategy.
type KayanOIDCRepository interface {
	// StoreOIDCState persists state, PKCE verifier, and nonce for the given TTL.
	StoreOIDCState(ctx context.Context, state, codeVerifier, nonce string, expiry time.Duration) error
	// ConsumeOIDCState retrieves and deletes the state record (single-use).
	// Returns ErrKayanOIDCStateInvalid if the state is unknown or expired.
	ConsumeOIDCState(ctx context.Context, state string) (codeVerifier, nonce string, err error)
	// FindOrCreateByProviderSub finds an existing identity by provider subject claim
	// or creates a new one from traits on first login.
	FindOrCreateByProviderSub(ctx context.Context, sub string, traits identity.JSON, factory func() any) (any, error)
}

// OIDCAuthorizationRequest is the transport-neutral input for constructing an
// authorization URL.
type OIDCAuthorizationRequest struct {
	State               string
	Nonce               string
	CodeChallenge       string
	CodeChallengeMethod string
}

// OIDCTokenExchangeRequest is the transport-neutral input for exchanging an
// authorization code.
type OIDCTokenExchangeRequest struct {
	Code         string
	CodeVerifier string
	RedirectURI  string
}

// OIDCTokenSet contains the token material Kayan consumes from an exchange.
// Access and refresh tokens intentionally do not cross this boundary.
type OIDCTokenSet struct {
	IDToken string
}

// OIDCClient performs the two external OAuth operations used by the strategy.
// Implementations may wrap any OAuth client library.
type OIDCClient interface {
	AuthorizationURL(request OIDCAuthorizationRequest) (string, error)
	Exchange(ctx context.Context, request OIDCTokenExchangeRequest) (*OIDCTokenSet, error)
}

// IDTokenParser verifies a raw OIDC ID token JWT and returns its claims.
// Implementations should fetch Kayan's public keys from <issuer>/oauth2/jwks.
type IDTokenParser interface {
	ParseAndVerify(rawIDToken, issuer, audience, expectedNonce string) (*IDTokenClaims, error)
}

// IDTokenClaims carries the verified claims from a Kayan-issued ID token.
type IDTokenClaims struct {
	Sub   string
	Email string
}

// KayanOIDCStrategy authenticates users via a Kayan instance acting as the OIDC provider.
// This is the client-side strategy for "Login with Kayan" flows.
//
// It satisfies LoginStrategy + Initiator (two-step: redirect → callback).
//
// Security invariants:
//   - state is cryptographically random (≥32 bytes), single-use, validated on callback (CSRF).
//   - PKCE S256 code_challenge + code_verifier used on every flow.
//   - nonce claim in the ID token is validated to prevent replay.
//   - Access token is never stored; only the Kayan session is issued.
type KayanOIDCStrategy struct {
	issuer      string
	clientID    string
	redirectURI string
	oauthClient OIDCClient
	tokenParser IDTokenParser
	repo        KayanOIDCRepository
	factory     func() any
}

// NewKayanOIDCStrategy creates a KayanOIDCStrategy.
func NewKayanOIDCStrategy(
	issuer, clientID, redirectURI string,
	oauthClient OIDCClient,
	tokenParser IDTokenParser,
	repo KayanOIDCRepository,
	factory func() any,
) *KayanOIDCStrategy {
	return &KayanOIDCStrategy{
		issuer:      issuer,
		clientID:    clientID,
		redirectURI: redirectURI,
		oauthClient: oauthClient,
		tokenParser: tokenParser,
		repo:        repo,
		factory:     factory,
	}
}

func (s *KayanOIDCStrategy) ID() string { return "kayan_oidc" }

// Initiate generates state + PKCE verifier + nonce, stores them, and returns the
// authorization URL to redirect the user to.
func (s *KayanOIDCStrategy) Initiate(ctx context.Context, _ string) (any, error) {
	state, err := generateSecureToken(32)
	if err != nil {
		return nil, fmt.Errorf("flow: kayan_oidc: generate state: %w", err)
	}
	verifier, err := generateSecureToken(32)
	if err != nil {
		return nil, fmt.Errorf("flow: kayan_oidc: generate verifier: %w", err)
	}
	nonce, err := generateSecureToken(16)
	if err != nil {
		return nil, fmt.Errorf("flow: kayan_oidc: generate nonce: %w", err)
	}

	if err := s.repo.StoreOIDCState(ctx, state, verifier, nonce, 10*time.Minute); err != nil {
		return nil, fmt.Errorf("flow: kayan_oidc: store state: %w", err)
	}

	digest := sha256.Sum256([]byte(verifier))
	url, err := s.oauthClient.AuthorizationURL(OIDCAuthorizationRequest{
		State:               state,
		Nonce:               nonce,
		CodeChallenge:       base64.RawURLEncoding.EncodeToString(digest[:]),
		CodeChallengeMethod: "S256",
	})
	if err != nil {
		return nil, fmt.Errorf("flow: kayan_oidc: authorization URL: %w", err)
	}
	return map[string]string{"redirect_url": url, "state": state}, nil
}

// Authenticate handles the OIDC callback: exchanges the code, verifies the ID token,
// and resolves (or creates) the local Kayan identity.
//
// identifier = state query parameter from the callback URL
// secret     = authorization code query parameter from the callback URL
func (s *KayanOIDCStrategy) Authenticate(ctx context.Context, state, code string) (any, error) {
	verifier, nonce, err := s.repo.ConsumeOIDCState(ctx, state)
	if err != nil {
		return nil, ErrKayanOIDCStateInvalid
	}

	tokens, err := s.oauthClient.Exchange(ctx, OIDCTokenExchangeRequest{
		Code:         code,
		CodeVerifier: verifier,
		RedirectURI:  s.redirectURI,
	})
	if err != nil {
		return nil, fmt.Errorf("flow: kayan_oidc: token exchange: %w", err)
	}

	if tokens == nil || tokens.IDToken == "" {
		return nil, ErrKayanOIDCMissingIDToken
	}

	claims, err := s.tokenParser.ParseAndVerify(tokens.IDToken, s.issuer, s.clientID, nonce)
	if err != nil {
		return nil, ErrKayanOIDCTokenInvalid
	}

	traits := identity.JSON(fmt.Sprintf(`{"sub":%q,"email":%q}`, claims.Sub, claims.Email))
	ident, err := s.repo.FindOrCreateByProviderSub(ctx, claims.Sub, traits, s.factory)
	if err != nil {
		return nil, fmt.Errorf("flow: kayan_oidc: resolve identity: %w", err)
	}
	return ident, nil
}
