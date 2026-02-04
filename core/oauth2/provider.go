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
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"strings"
	"time"

	"github.com/getkayan/kayan/core/audit"
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

func NewProvider(cs ClientStore, acs AuthCodeStore, rts RefreshTokenStore, issuer string, signingKey any, keyID string) *Provider {
	store, _ := cs.(audit.AuditStore)
	return &Provider{
		clientStore:       cs,
		authCodeStore:     acs,
		refreshTokenStore: rts,
		auditStore:        store,
		issuer:            issuer,
		signingKey:        signingKey,
		keyID:             keyID,
	}
}

// GenerateAuthCode generates a temporary code for the authorization flow with optional PKCE support.
func (p *Provider) GenerateAuthCode(ctx context.Context, clientID, identityID, redirectURI string, scopes []string, challenge, challengeMethod string) (string, error) {
	code := uuid.New().String()
	authCode := &AuthCode{
		Code:                code,
		ClientID:            clientID,
		IdentityID:          identityID,
		RedirectURI:         redirectURI,
		Scopes:              scopes,
		CodeChallenge:       challenge,
		CodeChallengeMethod: challengeMethod,
		ExpiresAt:           time.Now().Add(10 * time.Minute),
	}

	if err := p.authCodeStore.SaveAuthCode(ctx, authCode); err != nil {
		return "", err
	}
	return code, nil
}

// Exchange exchanges an authorization code for an access token response.
func (p *Provider) Exchange(ctx context.Context, code, clientID, clientSecret, redirectURI, verifier string) (*TokenResponse, error) {
	authCode, err := p.authCodeStore.GetAuthCode(ctx, code)
	if err != nil {
		p.logAudit(ctx, "oauth2.exchange.failure", clientID, "", "failure", "invalid authorization code")
		return nil, errors.New("invalid authorization code")
	}

	if authCode.ExpiresAt.Before(time.Now()) {
		p.authCodeStore.DeleteAuthCode(ctx, code)
		p.logAudit(ctx, "oauth2.exchange.failure", clientID, authCode.IdentityID, "failure", "authorization code expired")
		return nil, errors.New("authorization code expired")
	}

	if authCode.ClientID != clientID {
		return nil, errors.New("client id mismatch")
	}

	if authCode.RedirectURI != redirectURI {
		return nil, errors.New("redirect uri mismatch")
	}

	// PKCE Verification
	if authCode.CodeChallenge != "" {
		if !p.verifyPKCE(authCode.CodeChallenge, authCode.CodeChallengeMethod, verifier) {
			return nil, errors.New("invalid code verifier")
		}
	}

	// Validate client secret if provided
	if clientSecret != "" {
		_, err = p.ValidateClient(ctx, clientID, clientSecret)
		if err != nil {
			return nil, err
		}
	}

	// Important: Delete code after successful exchange
	p.authCodeStore.DeleteAuthCode(ctx, code)

	accessToken, err := p.GenerateAccessToken(clientID, authCode.IdentityID, authCode.Scopes)
	if err != nil {
		return nil, err
	}

	refreshTokenValue := uuid.New().String()
	refreshToken := &RefreshToken{
		Token:      refreshTokenValue,
		ClientID:   clientID,
		IdentityID: authCode.IdentityID,
		Scopes:     authCode.Scopes,
		ExpiresAt:  time.Now().Add(7 * 24 * time.Hour), // 7 days
	}

	if err := p.refreshTokenStore.SaveRefreshToken(ctx, refreshToken); err != nil {
		return nil, err
	}

	p.logAudit(ctx, "oauth2.exchange.success", clientID, authCode.IdentityID, "success", "")

	return &TokenResponse{
		AccessToken:  accessToken,
		TokenType:    "Bearer",
		ExpiresIn:    3600,
		RefreshToken: refreshTokenValue,
		Sub:          authCode.IdentityID,
	}, nil
}

// Refresh obtains a new access token using a refresh token and performs rotation.
func (p *Provider) Refresh(ctx context.Context, tokenValue, clientID, clientSecret string) (*TokenResponse, error) {
	// Validate client
	if clientSecret != "" {
		_, err := p.ValidateClient(ctx, clientID, clientSecret)
		if err != nil {
			return nil, err
		}
	}

	gr, err := p.refreshTokenStore.GetRefreshToken(ctx, tokenValue)
	if err != nil {
		return nil, errors.New("invalid refresh token")
	}

	if gr.ClientID != clientID {
		return nil, errors.New("client id mismatch")
	}

	if gr.ExpiresAt.Before(time.Now()) {
		p.refreshTokenStore.DeleteRefreshToken(ctx, tokenValue)
		return nil, errors.New("refresh token expired")
	}

	// Token Rotation: Delete old refresh token
	p.refreshTokenStore.DeleteRefreshToken(ctx, tokenValue)

	// Issue new tokens
	accessToken, err := p.GenerateAccessToken(clientID, gr.IdentityID, gr.Scopes)
	if err != nil {
		return nil, err
	}

	newRefreshTokenValue := uuid.New().String()
	newRefreshToken := &RefreshToken{
		Token:      newRefreshTokenValue,
		ClientID:   clientID,
		IdentityID: gr.IdentityID,
		Scopes:     gr.Scopes,
		ExpiresAt:  time.Now().Add(7 * 24 * time.Hour),
	}

	if err := p.refreshTokenStore.SaveRefreshToken(ctx, newRefreshToken); err != nil {
		return nil, err
	}

	return &TokenResponse{
		AccessToken:  accessToken,
		TokenType:    "Bearer",
		ExpiresIn:    3600,
		RefreshToken: newRefreshTokenValue,
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

func (p *Provider) verifyPKCE(challenge, method, verifier string) bool {
	if method == "" || strings.ToUpper(method) == "PLAIN" {
		return challenge == verifier
	}

	if strings.ToUpper(method) == "S256" {
		h := sha256.New()
		h.Write([]byte(verifier))
		hash := h.Sum(nil)
		expected := base64.RawURLEncoding.EncodeToString(hash)
		return challenge == expected
	}

	return false
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
func (p *Provider) ValidateClient(ctx context.Context, clientID, clientSecret string) (*Client, error) {
	client, err := p.clientStore.GetClient(ctx, clientID)
	if err != nil {
		return nil, err
	}

	if client.Secret != clientSecret {
		return nil, errors.New("invalid client secret")
	}

	return client, nil
}

// Introspect validates a token and returns its metadata.
func (p *Provider) Introspect(ctx context.Context, tokenString string) (*IntrospectionResponse, error) {
	token, err := jwt.Parse(tokenString, func(t *jwt.Token) (interface{}, error) {
		return p.signingKey, nil // Simplified, should use public key if verifying external
	})

	if err != nil || !token.Valid {
		return &IntrospectionResponse{Active: false}, nil
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return &IntrospectionResponse{Active: false}, nil
	}

	resp := &IntrospectionResponse{
		Active:   true,
		ClientID: claims["aud"].(string),
		Sub:      claims["sub"].(string),
		Exp:      int64(claims["exp"].(float64)),
		Iat:      int64(claims["iat"].(float64)),
		Iss:      claims["iss"].(string),
	}

	if scp, ok := claims["scp"].([]any); ok {
		scopes := make([]string, len(scp))
		for i, s := range scp {
			scopes[i] = s.(string)
		}
		resp.Scope = strings.Join(scopes, " ")
	}

	return resp, nil
}

// Revoke invalidates a token.
func (p *Provider) Revoke(ctx context.Context, tokenString string) error {
	// In a stateless JWT implementation, revocation requires a blacklist.
	// In a stateful implementation, we would delete the token from the store.
	// For now, this is a placeholder. A full implementation would involve
	// a RevocationStore or BlacklistStore.
	return nil
}
