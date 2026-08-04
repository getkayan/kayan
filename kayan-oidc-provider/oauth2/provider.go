// Package oauth2 provides OAuth 2.0 Authorization Server functionality for Kayan IAM.
//
// This package implements the OAuth 2.0 specification (RFC 6749) with support for
// the Authorization Code flow, PKCE (RFC 7636), token introspection (RFC 7662),
// and token refresh with rotation.
//
// # Features
//
//   - Authorization Code flow with PKCE support
//   - JWT access tokens with RSA-256 signing
//   - Refresh token rotation for security
//   - Token introspection endpoint
//   - Client credential validation
//   - Audit logging integration
//
// # Supported Flows
//
//   - Authorization Code (with optional PKCE)
//   - Refresh Token (with automatic rotation)
//
// # Example Usage
//
//	provider := oauth2.NewProvider(
//	    clientStore,
//	    authCodeStore,
//	    refreshTokenStore,
//	    "https://auth.example.com",
//	    privateKey,
//	    "key-1",
//	)
//
//	// Generate authorization code
//	code, _ := provider.GenerateAuthCode(ctx, clientID, userID, redirect, scopes, challenge, "S256")
//
//	// Exchange code for tokens
//	tokens, _ := provider.Exchange(ctx, code, clientID, secret, redirect, verifier)
//
//	// Refresh access token
//	newTokens, _ := provider.Refresh(ctx, refreshToken, clientID, secret)
package oauth2

import (
	"context"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/getkayan/kayan/core/audit"
	"github.com/getkayan/kayan/core/domain"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

type Provider struct {
	clientStore       ClientStore
	authCodeStore     AuthCodeStore
	refreshTokenStore RefreshTokenStore
	auditStore        audit.AuditStore
	issuer            string
	signingKey        any // RSA or ECDSA key
	keyID             string
	revocationStore   RevocationStore

	hasher       domain.Hasher
	tokens       domain.TokenGenerator
	clock        domain.Clock
	requirePKCE  bool
	allowPlainCC bool
}

// WithClientSecretHasher sets the hasher used to verify client secrets.
//
// It must be the same one used to hash [Client.SecretHash] at registration.
// Defaults to bcrypt.
func WithClientSecretHasher(h domain.Hasher) ProviderOption {
	return func(p *Provider) { p.hasher = h }
}

// WithTokenGenerator sets the source of authorization codes and refresh
// tokens. Defaults to [domain.DefaultTokenGenerator].
func WithTokenGenerator(g domain.TokenGenerator) ProviderOption {
	return func(p *Provider) { p.tokens = g }
}

// WithProviderClock sets the clock used for expiry. Defaults to
// [domain.SystemClock].
func WithProviderClock(c domain.Clock) ProviderOption {
	return func(p *Provider) { p.clock = c }
}

// WithRequirePKCE controls whether an authorization code must carry a PKCE
// challenge. Defaults to true.
//
// Disabling it allows an authorization code interception attack against public
// clients (RFC 7636 section 1). Turn it off only for a legacy confidential
// client that cannot be updated, and prefer scoping that to the client.
func WithRequirePKCE(require bool) ProviderOption {
	return func(p *Provider) { p.requirePKCE = require }
}

// WithAllowPlainCodeChallenge permits the "plain" PKCE method.
//
// Defaults to false. With "plain" the challenge is the verifier, so anyone who
// intercepts the authorization request can complete the exchange — the method
// exists only for clients that cannot compute SHA-256 (RFC 7636 section 4.2).
func WithAllowPlainCodeChallenge(allow bool) ProviderOption {
	return func(p *Provider) { p.allowPlainCC = allow }
}

// ProviderOption configures optional Provider behavior.
type ProviderOption func(*Provider)

// WithRevocationStore enables token revocation via the supplied store.
func WithRevocationStore(rs RevocationStore) ProviderOption {
	return func(p *Provider) { p.revocationStore = rs }
}

// IntrospectionResponse represents the response according to RFC 7662.
type IntrospectionResponse struct {
	Active   bool   `json:"active"`
	Scope    string `json:"scope,omitempty"`
	ClientID string `json:"client_id,omitempty"`
	Sub      string `json:"sub,omitempty"`
	Exp      int64  `json:"exp,omitempty"`
	Iat      int64  `json:"iat,omitempty"`
	Iss      string `json:"iss,omitempty"`
	Username string `json:"username,omitempty"`
}

// TokenResponse represents the response according to RFC 6749.
type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int64  `json:"expires_in"`
	RefreshToken string `json:"refresh_token,omitempty"`
	IDToken      string `json:"id_token,omitempty"`
	Sub          string `json:"sub,omitempty"`
}

func NewProvider(cs ClientStore, acs AuthCodeStore, rts RefreshTokenStore, issuer string, signingKey any, keyID string, opts ...ProviderOption) *Provider {
	store, _ := cs.(audit.AuditStore)
	p := &Provider{
		clientStore:       cs,
		authCodeStore:     acs,
		refreshTokenStore: rts,
		auditStore:        store,
		issuer:            issuer,
		signingKey:        signingKey,
		keyID:             keyID,
		// Secure by default: PKCE required, "plain" refused. Both are
		// swappable through options for callers who must interoperate with
		// something older.
		requirePKCE: true,
	}
	for _, opt := range opts {
		opt(p)
	}
	if p.hasher == nil {
		p.hasher = domain.NewBcryptHasher(0)
	}
	p.tokens = domain.TokenGeneratorOrDefault(p.tokens)
	p.clock = domain.ClockOrDefault(p.clock)
	return p
}

// GenerateAuthCode issues an authorization code.
//
// The redirect URI is checked against the client's registered allowlist, and a
// PKCE challenge is required unless the provider was built with
// WithRequirePKCE(false). Both checks happen here so a caller cannot reach the
// token endpoint with a code that was never validated.
func (p *Provider) GenerateAuthCode(ctx context.Context, clientID, identityID, redirectURI string, scopes []string, challenge, challengeMethod string) (string, error) {
	client, err := p.clientStore.GetClient(ctx, clientID)
	if err != nil {
		return "", ErrInvalidClient.WithDescription("unknown client").WithCause(err)
	}

	// Without this the authorization endpoint is an open redirector: an
	// attacker sends the victim through a legitimate authorization request and
	// receives the code at an address of their choosing.
	if !client.AllowsRedirectURI(redirectURI) {
		return "", ErrInvalidRequest.WithDescription("redirect_uri is not registered for this client")
	}

	if challenge == "" {
		// A public client cannot keep a secret, so PKCE is the only thing
		// binding the code to the requester.
		if p.requirePKCE || client.IsPublic() {
			return "", ErrInvalidRequest.WithDescription("code_challenge is required")
		}
	} else {
		method := normalizeChallengeMethod(challengeMethod)
		if method == challengeMethodPlain && !p.allowPlainCC {
			return "", ErrInvalidRequest.WithDescription("code_challenge_method must be S256")
		}
		if method == "" {
			return "", ErrInvalidRequest.WithDescription("unsupported code_challenge_method")
		}
		// Store the resolved method so the exchange cannot reinterpret an
		// absent value as "plain".
		challengeMethod = method
	}

	code, err := p.tokens()
	if err != nil {
		return "", ErrServerError.WithCause(err)
	}

	authCode := &AuthCode{
		Code:                code,
		ClientID:            clientID,
		IdentityID:          identityID,
		RedirectURI:         redirectURI,
		Scopes:              scopes,
		CodeChallenge:       challenge,
		CodeChallengeMethod: challengeMethod,
		ExpiresAt:           p.clock.Now().Add(authCodeTTL),
	}

	if err := p.authCodeStore.SaveAuthCode(ctx, authCode); err != nil {
		return "", ErrServerError.WithCause(err)
	}
	return code, nil
}

// Grant types this provider understands.
const (
	GrantAuthorizationCode = "authorization_code"
	GrantRefreshToken      = "refresh_token"
)

// authCodeTTL bounds how long an authorization code is valid. RFC 6749
// section 4.1.2 recommends a maximum of ten minutes.
const authCodeTTL = 10 * time.Minute

// Exchange exchanges an authorization code for an access token response.
//
// The client is authenticated first, so an unauthenticated caller learns
// nothing about whether a code exists.
func (p *Provider) Exchange(ctx context.Context, code, clientID, clientSecret, redirectURI, verifier string) (*TokenResponse, error) {
	// Authenticate before touching the code store. Client authentication was
	// previously skipped whenever the secret was empty, so a confidential
	// client could be impersonated by simply omitting it.
	if _, err := p.authenticate(ctx, clientID, clientSecret, GrantAuthorizationCode); err != nil {
		p.logAudit(ctx, "oauth2.exchange.failure", clientID, "", "failure", "client authentication failed")
		return nil, err
	}

	authCode, err := p.authCodeStore.GetAuthCode(ctx, code)
	if err != nil {
		p.logAudit(ctx, "oauth2.exchange.failure", clientID, "", "failure", "invalid authorization code")
		return nil, ErrInvalidGrant.WithDescription("invalid authorization code").WithCause(err)
	}

	// The code is single-use regardless of what happens next. Leaving it live
	// after a failed exchange would allow retrying the other checks.
	defer func() { _ = p.authCodeStore.DeleteAuthCode(ctx, code) }()

	if !p.clock.Now().Before(authCode.ExpiresAt) {
		p.logAudit(ctx, "oauth2.exchange.failure", clientID, authCode.IdentityID, "failure", "authorization code expired")
		return nil, ErrInvalidGrant.WithDescription("authorization code expired")
	}

	if authCode.ClientID != clientID {
		// The code belongs to another client: this is a code injection
		// attempt, not a mistake.
		p.logAudit(ctx, "oauth2.exchange.failure", clientID, authCode.IdentityID, "failure", "authorization code issued to a different client")
		return nil, ErrInvalidGrant.WithDescription("invalid authorization code")
	}

	if authCode.RedirectURI != redirectURI {
		return nil, ErrInvalidGrant.WithDescription("redirect_uri does not match the authorization request")
	}

	if err := p.verifyCodeChallenge(authCode, verifier); err != nil {
		p.logAudit(ctx, "oauth2.exchange.failure", clientID, authCode.IdentityID, "failure", "PKCE verification failed")
		return nil, err
	}

	accessToken, err := p.GenerateAccessToken(clientID, authCode.IdentityID, authCode.Scopes)
	if err != nil {
		return nil, ErrServerError.WithCause(err)
	}

	refreshValue, err := p.issueRefreshToken(ctx, clientID, authCode.IdentityID, authCode.Scopes, "")
	if err != nil {
		return nil, err
	}

	p.logAudit(ctx, "oauth2.exchange.success", clientID, authCode.IdentityID, "success", "")

	return &TokenResponse{
		AccessToken:  accessToken,
		TokenType:    "Bearer",
		ExpiresIn:    int64(accessTokenTTL.Seconds()),
		RefreshToken: refreshValue,
		Sub:          authCode.IdentityID,
	}, nil
}

// verifyCodeChallenge checks PKCE for an authorization code.
//
// A code with no challenge is rejected when PKCE is required, so a client
// cannot opt out by omitting the challenge.
func (p *Provider) verifyCodeChallenge(authCode *AuthCode, verifier string) error {
	if authCode.CodeChallenge == "" {
		if p.requirePKCE {
			return ErrInvalidGrant.WithDescription("code_challenge is required")
		}
		return nil
	}

	if verifier == "" {
		return ErrInvalidGrant.WithDescription("code_verifier is required")
	}
	if !p.verifyPKCE(authCode.CodeChallenge, authCode.CodeChallengeMethod, verifier) {
		return ErrInvalidGrant.WithDescription("invalid code_verifier")
	}
	return nil
}

// issueRefreshToken saves a new refresh token, continuing familyID when given.
func (p *Provider) issueRefreshToken(ctx context.Context, clientID, identityID string, scopes []string, familyID string) (string, error) {
	value, err := p.tokens()
	if err != nil {
		return "", ErrServerError.WithCause(err)
	}
	if familyID == "" {
		familyID, err = p.tokens()
		if err != nil {
			return "", ErrServerError.WithCause(err)
		}
	}

	token := &RefreshToken{
		Token:      value,
		ClientID:   clientID,
		IdentityID: identityID,
		Scopes:     scopes,
		ExpiresAt:  p.clock.Now().Add(refreshTokenTTL),
		FamilyID:   familyID,
	}
	if err := p.refreshTokenStore.SaveRefreshToken(ctx, token); err != nil {
		return "", ErrServerError.WithCause(err)
	}
	return value, nil
}

// Token lifetimes.
const (
	accessTokenTTL  = time.Hour
	refreshTokenTTL = 7 * 24 * time.Hour
)

// Refresh exchanges a refresh token for a new access token, rotating the
// refresh token.
//
// When the store implements [RefreshTokenFamilyStore], a redeemed token stays
// resolvable and a second presentation revokes the whole family. That is the
// only signal available that a refresh token was stolen: the legitimate client
// and the thief both hold a token from the same chain, and whichever presents
// a spent one proves the chain is compromised.
//
// With a plain [RefreshTokenStore] the redeemed token is deleted instead, so a
// replay is reported as invalid but the thief's token continues to work.
func (p *Provider) Refresh(ctx context.Context, tokenValue, clientID, clientSecret string) (*TokenResponse, error) {
	// Authenticate first: previously an empty secret skipped this entirely.
	if _, err := p.authenticate(ctx, clientID, clientSecret, GrantRefreshToken); err != nil {
		p.logAudit(ctx, "oauth2.refresh.failure", clientID, "", "failure", "client authentication failed")
		return nil, err
	}

	family, hasFamily := p.refreshTokenStore.(RefreshTokenFamilyStore)

	gr, err := p.refreshTokenStore.GetRefreshToken(ctx, tokenValue)
	if err != nil {
		return nil, ErrInvalidGrant.WithDescription("invalid refresh token").WithCause(err)
	}

	if gr.ClientID != clientID {
		return nil, ErrInvalidGrant.WithDescription("invalid refresh token")
	}

	// Reuse detection. A token presented twice means two parties hold it, so
	// every token descended from the same authorization is revoked and the
	// legitimate client is forced to re-authenticate.
	if gr.IsUsed() {
		p.logAudit(ctx, "oauth2.refresh.reuse", clientID, gr.IdentityID, "failure",
			"refresh token replayed; revoking the token family")
		if hasFamily && gr.FamilyID != "" {
			if err := family.RevokeFamily(ctx, gr.FamilyID); err != nil {
				return nil, ErrServerError.WithCause(err)
			}
		} else {
			_ = p.refreshTokenStore.DeleteRefreshToken(ctx, tokenValue)
		}
		return nil, ErrInvalidGrant.WithDescription("invalid refresh token")
	}

	if !p.clock.Now().Before(gr.ExpiresAt) {
		_ = p.refreshTokenStore.DeleteRefreshToken(ctx, tokenValue)
		return nil, ErrInvalidGrant.WithDescription("refresh token expired")
	}

	// Rotate. With family tracking the spent token is retained and marked, so
	// a later replay is detectable; otherwise it is deleted.
	if hasFamily {
		if err := family.MarkRefreshTokenUsed(ctx, tokenValue, p.clock.Now()); err != nil {
			return nil, ErrServerError.WithCause(err)
		}
	} else if err := p.refreshTokenStore.DeleteRefreshToken(ctx, tokenValue); err != nil {
		return nil, ErrServerError.WithCause(err)
	}

	accessToken, err := p.GenerateAccessToken(clientID, gr.IdentityID, gr.Scopes)
	if err != nil {
		return nil, ErrServerError.WithCause(err)
	}

	newValue, err := p.issueRefreshToken(ctx, clientID, gr.IdentityID, gr.Scopes, gr.FamilyID)
	if err != nil {
		return nil, err
	}

	p.logAudit(ctx, "oauth2.refresh.success", clientID, gr.IdentityID, "success", "")

	return &TokenResponse{
		AccessToken:  accessToken,
		TokenType:    "Bearer",
		ExpiresIn:    int64(accessTokenTTL.Seconds()),
		RefreshToken: newValue,
		Sub:          gr.IdentityID,
	}, nil
}

func (p *Provider) logAudit(ctx context.Context, eventType, actor, subject, status, message string) {
	if p.auditStore == nil {
		return
	}
	p.auditStore.SaveEvent(ctx, &audit.AuditEvent{
		Type:      eventType,
		ActorID:   actor,
		SubjectID: subject,
		Status:    status,
		Message:   message,
	})
}

// PKCE code challenge methods (RFC 7636 section 4.2).
const (
	challengeMethodS256  = "S256"
	challengeMethodPlain = "plain"
)

// normalizeChallengeMethod canonicalizes a code_challenge_method, returning ""
// for anything unrecognized.
//
// An empty method is *not* treated as "plain". RFC 7636 defaults an omitted
// method to plain, but accepting that at verification lets an attacker who
// intercepts an authorization request strip the method and replay the
// challenge as its own verifier. GenerateAuthCode resolves the method up
// front, so by the time a code is verified the field is always explicit.
func normalizeChallengeMethod(method string) string {
	switch strings.ToUpper(method) {
	case "S256":
		return challengeMethodS256
	case "PLAIN":
		return challengeMethodPlain
	default:
		return ""
	}
}

// verifyPKCE checks a code verifier against the stored challenge.
func (p *Provider) verifyPKCE(challenge, method, verifier string) bool {
	switch normalizeChallengeMethod(method) {
	case challengeMethodS256:
		sum := sha256.Sum256([]byte(verifier))
		expected := base64.RawURLEncoding.EncodeToString(sum[:])
		return subtle.ConstantTimeCompare([]byte(challenge), []byte(expected)) == 1

	case challengeMethodPlain:
		// Only reachable when the provider was explicitly built to allow it.
		if !p.allowPlainCC {
			return false
		}
		return subtle.ConstantTimeCompare([]byte(challenge), []byte(verifier)) == 1

	default:
		// An unknown or absent method fails closed rather than degrading to a
		// plaintext comparison.
		return false
	}
}

// GenerateAccessToken generates a signed JWT access token for a user.
func (p *Provider) GenerateAccessToken(clientID string, identityID string, scopes []string) (string, error) {
	claims := jwt.MapClaims{
		"iss": p.issuer,
		"sub": identityID,
		"aud": clientID,
		"exp": time.Now().Add(1 * time.Hour).Unix(),
		"iat": time.Now().Unix(),
		"jti": uuid.New().String(),
		"scp": scopes,
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = p.keyID

	return token.SignedString(p.signingKey)
}

// ValidateClient validates the client ID and secret.
// ValidateClient authenticates a client at the token endpoint.
//
// Confidential clients must present a secret; it is verified against the
// stored hash with the configured [domain.Hasher], never compared directly.
// Public clients — those registered with [AuthMethodNone] — authenticate with
// no secret and rely on PKCE instead.
//
// The error is the same whether the client is unknown or the secret is wrong,
// so the endpoint cannot be used to enumerate client IDs.
func (p *Provider) ValidateClient(ctx context.Context, clientID, clientSecret string) (*Client, error) {
	client, err := p.clientStore.GetClient(ctx, clientID)
	if err != nil {
		// Spend comparable time on an unknown client so response timing does
		// not distinguish "no such client" from "wrong secret".
		if clientSecret != "" {
			_ = p.hasher.Compare(clientSecret, dummyBcryptHash)
		}
		return nil, ErrInvalidClient.WithDescription("client authentication failed").WithCause(err)
	}

	if client.IsPublic() {
		// A public client has no secret. Presenting one means the caller is
		// confused about the registration, so refuse rather than ignore it.
		if clientSecret != "" {
			return nil, ErrInvalidClient.WithDescription("client authentication failed")
		}
		return client, nil
	}

	// Confidential client: a secret is mandatory. Previously an empty secret
	// skipped verification entirely, so omitting it authenticated the client.
	if clientSecret == "" {
		return nil, ErrInvalidClient.WithDescription("client authentication failed")
	}
	if client.SecretHash == "" {
		// Registered as confidential but with no stored hash. Fail closed:
		// treating this as "no secret required" authenticates anyone.
		return nil, ErrInvalidClient.WithDescription("client authentication failed")
	}
	if !p.hasher.Compare(clientSecret, client.SecretHash) {
		return nil, ErrInvalidClient.WithDescription("client authentication failed")
	}

	return client, nil
}

// dummyBcryptHash is a valid bcrypt hash of a value no caller will present. It
// gives the unknown-client path the same work as a real verification.
const dummyBcryptHash = "$2a$12$C6UzMDM.H6dfI/f/IKcEe.QGxuAyxRkiSVJ5wZ5aVXo0nSFQPBpBu"

// authenticate resolves and authenticates the client for a token request.
func (p *Provider) authenticate(ctx context.Context, clientID, clientSecret, grantType string) (*Client, error) {
	client, err := p.ValidateClient(ctx, clientID, clientSecret)
	if err != nil {
		return nil, err
	}
	if !client.AllowsGrantType(grantType) {
		return nil, ErrUnauthorizedClient.WithDescriptionf("client may not use the %s grant", grantType)
	}
	return client, nil
}

// Introspect validates a token and returns its metadata.
func (p *Provider) Introspect(ctx context.Context, tokenString string) (*IntrospectionResponse, error) {
	token, err := jwt.Parse(tokenString, func(t *jwt.Token) (interface{}, error) {
		return verificationKey(p.signingKey), nil
	})

	if err != nil || !token.Valid {
		return &IntrospectionResponse{Active: false}, nil
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return &IntrospectionResponse{Active: false}, nil
	}

	// Check revocation
	if p.revocationStore != nil {
		if jti, ok := claimString(claims, "jti"); ok {
			revoked, err := p.revocationStore.IsRevoked(ctx, jti)
			if err == nil && revoked {
				return &IntrospectionResponse{Active: false}, nil
			}
		}
	}

	clientID, ok := claimString(claims, "aud")
	if !ok {
		return &IntrospectionResponse{Active: false}, nil
	}
	sub, ok := claimString(claims, "sub")
	if !ok {
		return &IntrospectionResponse{Active: false}, nil
	}
	iss, ok := claimString(claims, "iss")
	if !ok {
		return &IntrospectionResponse{Active: false}, nil
	}
	exp, ok := claimInt64(claims, "exp")
	if !ok {
		return &IntrospectionResponse{Active: false}, nil
	}
	iat, ok := claimInt64(claims, "iat")
	if !ok {
		return &IntrospectionResponse{Active: false}, nil
	}

	resp := &IntrospectionResponse{
		Active:   true,
		ClientID: clientID,
		Sub:      sub,
		Exp:      exp,
		Iat:      iat,
		Iss:      iss,
	}

	if scopes, ok := claimStringSlice(claims, "scp"); ok {
		resp.Scope = strings.Join(scopes, " ")
	}

	return resp, nil
}

func verificationKey(signingKey any) any {
	switch key := signingKey.(type) {
	case *rsa.PrivateKey:
		return &key.PublicKey
	case *ecdsa.PrivateKey:
		return &key.PublicKey
	default:
		return signingKey
	}
}

func claimString(claims jwt.MapClaims, key string) (string, bool) {
	value, ok := claims[key]
	if !ok {
		return "", false
	}
	switch typed := value.(type) {
	case string:
		return typed, true
	case []any:
		if len(typed) == 0 {
			return "", false
		}
		first, ok := typed[0].(string)
		return first, ok
	default:
		return "", false
	}
}

func claimInt64(claims jwt.MapClaims, key string) (int64, bool) {
	value, ok := claims[key]
	if !ok {
		return 0, false
	}
	switch typed := value.(type) {
	case float64:
		return int64(typed), true
	case int64:
		return typed, true
	case int:
		return int64(typed), true
	default:
		return 0, false
	}
}

func claimStringSlice(claims jwt.MapClaims, key string) ([]string, bool) {
	value, ok := claims[key]
	if !ok {
		return nil, false
	}
	switch typed := value.(type) {
	case []string:
		return typed, true
	case []any:
		scopes := make([]string, 0, len(typed))
		for _, item := range typed {
			str, ok := item.(string)
			if !ok {
				return nil, false
			}
			scopes = append(scopes, str)
		}
		return scopes, true
	default:
		return nil, false
	}
}

// Revoke invalidates a token by storing its JTI in the revocation store.
// Per RFC 7009, the token is parsed without full verification to extract claims.
func (p *Provider) Revoke(ctx context.Context, tokenString string) error {
	if p.revocationStore == nil {
		return nil // no-op when revocation is not configured
	}

	// Parse without verification to extract jti and exp (RFC 7009 allows this).
	parser := jwt.NewParser(jwt.WithoutClaimsValidation())
	token, _, err := parser.ParseUnverified(tokenString, jwt.MapClaims{})
	if err != nil {
		return errors.New("oauth2: invalid token format")
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return errors.New("oauth2: invalid token claims")
	}

	jti, ok := claimString(claims, "jti")
	if !ok || jti == "" {
		return errors.New("oauth2: token missing jti claim")
	}

	var expiresAt time.Time
	if exp, ok := claimInt64(claims, "exp"); ok {
		expiresAt = time.Unix(exp, 0)
	} else {
		expiresAt = time.Now().Add(24 * time.Hour) // fallback: keep revocation for 24h
	}

	if err := p.revocationStore.RevokeToken(ctx, jti, expiresAt); err != nil {
		return fmt.Errorf("oauth2: revocation failed: %w", err)
	}

	p.logAudit(ctx, "oauth2.revoke.success", "", "", "success", "token revoked")
	return nil
}
