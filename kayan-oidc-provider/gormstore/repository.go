// Package gormstore persists OAuth 2.0 clients, authorization codes, and
// refresh tokens with GORM.
//
// It is one implementation of the oauth2 storage interfaces. Any other backend
// satisfies the same interfaces and drops in without changes elsewhere.
package gormstore

import (
	"context"
	"time"

	"github.com/getkayan/kayan/kayan-oidc-provider/oauth2"
	"gorm.io/gorm"
)

// OAuth2Repository handles OAuth2 client, auth code, and refresh token persistence.
type OAuth2Repository struct {
	db *gorm.DB
}

// NewOAuth2Repository creates a new OAuth2Repository.
func NewOAuth2Repository(db *gorm.DB) *OAuth2Repository {
	return &OAuth2Repository{db: db}
}

func (r *OAuth2Repository) GetClient(ctx context.Context, id string) (*oauth2.Client, error) {
	var gc gormClient
	if err := r.db.WithContext(ctx).First(&gc, "id = ?", id).Error; err != nil {
		return nil, err
	}
	return toCoreClient(&gc), nil
}

func (r *OAuth2Repository) CreateClient(ctx context.Context, client *oauth2.Client) error {
	gc := fromCoreClient(client)
	return r.db.WithContext(ctx).Create(gc).Error
}

func (r *OAuth2Repository) DeleteClient(ctx context.Context, id string) error {
	return r.db.WithContext(ctx).Delete(&gormClient{}, "id = ?", id).Error
}

func (r *OAuth2Repository) SaveAuthCode(ctx context.Context, code *oauth2.AuthCode) error {
	gc := fromCoreAuthCode(code)
	return r.db.WithContext(ctx).Save(gc).Error
}

func (r *OAuth2Repository) GetAuthCode(ctx context.Context, code string) (*oauth2.AuthCode, error) {
	var gc gormAuthCode
	if err := r.db.WithContext(ctx).First(&gc, "code = ?", code).Error; err != nil {
		return nil, err
	}
	return toCoreAuthCode(&gc), nil
}

func (r *OAuth2Repository) DeleteAuthCode(ctx context.Context, code string) error {
	return r.db.WithContext(ctx).Delete(&gormAuthCode{}, "code = ?", code).Error
}

func (r *OAuth2Repository) SaveRefreshToken(ctx context.Context, token *oauth2.RefreshToken) error {
	gr := fromCoreRefreshToken(token)
	return r.db.WithContext(ctx).Save(gr).Error
}

func (r *OAuth2Repository) GetRefreshToken(ctx context.Context, token string) (*oauth2.RefreshToken, error) {
	var gr gormRefreshToken
	if err := r.db.WithContext(ctx).First(&gr, "token = ?", token).Error; err != nil {
		return nil, err
	}
	return toCoreRefreshToken(&gr), nil
}

func (r *OAuth2Repository) DeleteRefreshToken(ctx context.Context, token string) error {
	return r.db.WithContext(ctx).Delete(&gormRefreshToken{}, "token = ?", token).Error
}

// MarkRefreshTokenUsed implements [oauth2.RefreshTokenFamilyStore].
//
// The token is retained rather than deleted so that a later replay is
// detectable — deleting it would make a stolen token indistinguishable from an
// unknown one.
func (r *OAuth2Repository) MarkRefreshTokenUsed(ctx context.Context, token string, usedAt time.Time) error {
	res := r.db.WithContext(ctx).
		Model(&gormRefreshToken{}).
		Where("token = ? AND used_at IS NULL", token).
		Update("used_at", usedAt)
	if res.Error != nil {
		return res.Error
	}
	if res.RowsAffected == 0 {
		// Either the token is gone or another request marked it first. Report
		// it so the caller does not issue a second token for one redemption.
		return gorm.ErrRecordNotFound
	}
	return nil
}

// RevokeFamily implements [oauth2.RefreshTokenFamilyStore].
func (r *OAuth2Repository) RevokeFamily(ctx context.Context, familyID string) error {
	if familyID == "" {
		return nil
	}
	return r.db.WithContext(ctx).Delete(&gormRefreshToken{}, "family_id = ?", familyID).Error
}

// DeleteExpiredRefreshTokens removes tokens past their expiry, including spent
// ones retained for replay detection.
func (r *OAuth2Repository) DeleteExpiredRefreshTokens(ctx context.Context, olderThan time.Time) (int64, error) {
	res := r.db.WithContext(ctx).Delete(&gormRefreshToken{}, "expires_at < ?", olderThan)
	return res.RowsAffected, res.Error
}

// Compile-time proof that this repository supports reuse detection.
var _ oauth2.RefreshTokenFamilyStore = (*OAuth2Repository)(nil)

// ListClients returns all registered OAuth2 clients.
// Implements the oidc.ClientLister interface for backchannel logout support.
func (r *OAuth2Repository) ListClients(ctx context.Context) ([]*oauth2.Client, error) {
	var clients []gormClient
	if err := r.db.WithContext(ctx).Find(&clients).Error; err != nil {
		return nil, err
	}
	result := make([]*oauth2.Client, len(clients))
	for i := range clients {
		result[i] = toCoreClient(&clients[i])
	}
	return result, nil
}

type gormClient struct {
	ID string `gorm:"primaryKey"`
	// SecretHash stores the hashed client secret. The plaintext secret is
	// never persisted, so a database disclosure does not hand over every
	// client credential.
	SecretHash              string
	RedirectURIs            []string `gorm:"type:text;serializer:json"`
	GrantTypes              []string `gorm:"type:text;serializer:json"`
	Scopes                  []string `gorm:"type:text;serializer:json"`
	AppName                 string
	TokenEndpointAuthMethod string
	BackChannelLogoutURI    string
	// PostLogoutRedirectURIs is the allowlist RP-initiated logout checks a
	// post_logout_redirect_uri against. Omitting the column did not weaken
	// that check -- it emptied the allowlist, so every registered target was
	// refused.
	PostLogoutRedirectURIs []string `gorm:"type:text;serializer:json"`
	// JWKS holds the client's registered public keys for private_key_jwt.
	// It is a JWKS document, not a secret: only public halves belong here.
	JWKS []byte `gorm:"type:text"`
}

func (gormClient) TableName() string { return "oauth2_clients" }

func toCoreClient(gc *gormClient) *oauth2.Client {
	if gc == nil {
		return nil
	}
	return &oauth2.Client{
		ID:                      gc.ID,
		SecretHash:              gc.SecretHash,
		RedirectURIs:            gc.RedirectURIs,
		GrantTypes:              gc.GrantTypes,
		Scopes:                  gc.Scopes,
		AppName:                 gc.AppName,
		TokenEndpointAuthMethod: gc.TokenEndpointAuthMethod,
		BackChannelLogoutURI:    gc.BackChannelLogoutURI,
		PostLogoutRedirectURIs:  gc.PostLogoutRedirectURIs,
		JWKS:                    gc.JWKS,
	}
}

func fromCoreClient(c *oauth2.Client) *gormClient {
	if c == nil {
		return nil
	}
	return &gormClient{
		ID:                      c.ID,
		SecretHash:              c.SecretHash,
		RedirectURIs:            c.RedirectURIs,
		GrantTypes:              c.GrantTypes,
		Scopes:                  c.Scopes,
		AppName:                 c.AppName,
		TokenEndpointAuthMethod: c.TokenEndpointAuthMethod,
		BackChannelLogoutURI:    c.BackChannelLogoutURI,
		PostLogoutRedirectURIs:  c.PostLogoutRedirectURIs,
		JWKS:                    c.JWKS,
	}
}

type gormAuthCode struct {
	Code                string `gorm:"primaryKey"`
	ClientID            string `gorm:"index"`
	IdentityID          string `gorm:"index"`
	RedirectURI         string
	Scopes              []string `gorm:"type:text;serializer:json"`
	CodeChallenge       string
	CodeChallengeMethod string
	// Nonce binds the ID token issued from this code to the authorization
	// request that produced it. Dropping it here silently removed that
	// binding for every deployment on this adapter.
	Nonce string
	// AuthTime, ACR, and AMR record what the sign-in behind this code actually
	// was. MaxAgeSeconds records what the authorization request demanded of
	// it. Dropping any of them would leave the token endpoint unable to tell
	// whether max_age was honoured.
	AuthTime      time.Time
	ACR           string
	AMR           []string `gorm:"type:text;serializer:json"`
	MaxAgeSeconds *int
	ExpiresAt     time.Time `gorm:"index"`
}

func (gormAuthCode) TableName() string { return "oauth2_auth_codes" }

func toCoreAuthCode(gc *gormAuthCode) *oauth2.AuthCode {
	if gc == nil {
		return nil
	}
	return &oauth2.AuthCode{
		Code:                gc.Code,
		ClientID:            gc.ClientID,
		IdentityID:          gc.IdentityID,
		RedirectURI:         gc.RedirectURI,
		Scopes:              gc.Scopes,
		CodeChallenge:       gc.CodeChallenge,
		CodeChallengeMethod: gc.CodeChallengeMethod,
		Nonce:               gc.Nonce,
		AuthTime:            gc.AuthTime,
		ACR:                 gc.ACR,
		AMR:                 gc.AMR,
		MaxAgeSeconds:       gc.MaxAgeSeconds,
		ExpiresAt:           gc.ExpiresAt,
	}
}

func fromCoreAuthCode(c *oauth2.AuthCode) *gormAuthCode {
	if c == nil {
		return nil
	}
	return &gormAuthCode{
		Code:                c.Code,
		ClientID:            c.ClientID,
		IdentityID:          c.IdentityID,
		RedirectURI:         c.RedirectURI,
		Scopes:              c.Scopes,
		CodeChallenge:       c.CodeChallenge,
		CodeChallengeMethod: c.CodeChallengeMethod,
		Nonce:               c.Nonce,
		AuthTime:            c.AuthTime,
		ACR:                 c.ACR,
		AMR:                 c.AMR,
		MaxAgeSeconds:       c.MaxAgeSeconds,
		ExpiresAt:           c.ExpiresAt,
	}
}

type gormRefreshToken struct {
	Token      string    `gorm:"primaryKey"`
	ClientID   string    `gorm:"index"`
	IdentityID string    `gorm:"index"`
	Scopes     []string  `gorm:"type:text;serializer:json"`
	ExpiresAt  time.Time `gorm:"index"`
	// FamilyID links tokens descended from one authorization, so replaying a
	// spent token can revoke the whole chain.
	FamilyID string `gorm:"index"`
	// UsedAt marks a redeemed token. Redeemed tokens are retained rather than
	// deleted: that is what makes a replay distinguishable from an unknown
	// token.
	UsedAt *time.Time
}

func (gormRefreshToken) TableName() string { return "oauth2_refresh_tokens" }

func toCoreRefreshToken(gr *gormRefreshToken) *oauth2.RefreshToken {
	if gr == nil {
		return nil
	}
	return &oauth2.RefreshToken{
		FamilyID:   gr.FamilyID,
		UsedAt:     gr.UsedAt,
		Token:      gr.Token,
		ClientID:   gr.ClientID,
		IdentityID: gr.IdentityID,
		Scopes:     gr.Scopes,
		ExpiresAt:  gr.ExpiresAt,
	}
}

func fromCoreRefreshToken(r *oauth2.RefreshToken) *gormRefreshToken {
	if r == nil {
		return nil
	}
	return &gormRefreshToken{
		FamilyID:   r.FamilyID,
		UsedAt:     r.UsedAt,
		Token:      r.Token,
		ClientID:   r.ClientID,
		IdentityID: r.IdentityID,
		Scopes:     r.Scopes,
		ExpiresAt:  r.ExpiresAt,
	}
}

// AutoMigrate creates the tables this repository needs.
//
// For development only. Production deployments should run versioned
// migrations; see the module README.
func (r *OAuth2Repository) AutoMigrate() error {
	return r.db.AutoMigrate(
		&gormClient{},
		&gormAuthCode{},
		&gormRefreshToken{},
	)
}
