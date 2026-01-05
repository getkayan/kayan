package oauth2

import (
	"context"
	"errors"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

type Provider struct {
	clientStore   ClientStore
	authCodeStore AuthCodeStore
	issuer        string
	signingKey    any // RSA or ECDSA key
	keyID         string
}

func NewProvider(cs ClientStore, acs AuthCodeStore, issuer string, signingKey any, keyID string) *Provider {
	return &Provider{
		clientStore:   cs,
		authCodeStore: acs,
		issuer:        issuer,
		signingKey:    signingKey,
		keyID:         keyID,
	}
}

// GenerateAuthCode generates a temporary code for the authorization flow.
func (p *Provider) GenerateAuthCode(ctx context.Context, clientID, identityID, redirectURI string, scopes []string) (string, error) {
	code := uuid.New().String()
	authCode := &AuthCode{
		Code:        code,
		ClientID:    clientID,
		IdentityID:  identityID,
		RedirectURI: redirectURI,
		Scopes:      scopes,
		ExpiresAt:   time.Now().Add(10 * time.Minute),
	}

	if err := p.authCodeStore.SaveAuthCode(ctx, authCode); err != nil {
		return "", err
	}
	return code, nil
}

// Exchange exchanges an authorization code for an access token.
func (p *Provider) Exchange(ctx context.Context, code, clientID, clientSecret, redirectURI string) (string, error) {
	authCode, err := p.authCodeStore.GetAuthCode(ctx, code)
	if err != nil {
		return "", errors.New("invalid authorization code")
	}

	if authCode.ExpiresAt.Before(time.Now()) {
		p.authCodeStore.DeleteAuthCode(ctx, code)
		return "", errors.New("authorization code expired")
	}

	if authCode.ClientID != clientID {
		return "", errors.New("client id mismatch")
	}

	if authCode.RedirectURI != redirectURI {
		return "", errors.New("redirect uri mismatch")
	}

	// Validate client secret
	_, err = p.ValidateClient(ctx, clientID, clientSecret)
	if err != nil {
		return "", err
	}

	// Important: Delete code after successful exchange
	p.authCodeStore.DeleteAuthCode(ctx, code)

	return p.GenerateAccessToken(clientID, authCode.IdentityID, authCode.Scopes)
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
