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
	ID                   string `gorm:"primaryKey"`
	Secret               string
	RedirectURIs         []string `gorm:"type:text;serializer:json"`
	GrantTypes           []string `gorm:"type:text;serializer:json"`
	Scopes               []string `gorm:"type:text;serializer:json"`
	AppName              string
	BackChannelLogoutURI string
}

func (gormClient) TableName() string { return "oauth2_clients" }

func toCoreClient(gc *gormClient) *oauth2.Client {
	if gc == nil {
		return nil
	}
	return &oauth2.Client{
		ID:                   gc.ID,
		Secret:               gc.Secret,
		RedirectURIs:         gc.RedirectURIs,
		GrantTypes:           gc.GrantTypes,
		Scopes:               gc.Scopes,
		AppName:              gc.AppName,
		BackChannelLogoutURI: gc.BackChannelLogoutURI,
	}
}

func fromCoreClient(c *oauth2.Client) *gormClient {
	if c == nil {
		return nil
	}
	return &gormClient{
		ID:                   c.ID,
		Secret:               c.Secret,
		RedirectURIs:         c.RedirectURIs,
		GrantTypes:           c.GrantTypes,
		Scopes:               c.Scopes,
		AppName:              c.AppName,
		BackChannelLogoutURI: c.BackChannelLogoutURI,
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
	ExpiresAt           time.Time `gorm:"index"`
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
		ExpiresAt:           c.ExpiresAt,
	}
}

type gormRefreshToken struct {
	Token      string    `gorm:"primaryKey"`
	ClientID   string    `gorm:"index"`
	IdentityID string    `gorm:"index"`
	Scopes     []string  `gorm:"type:text;serializer:json"`
	ExpiresAt  time.Time `gorm:"index"`
}

func (gormRefreshToken) TableName() string { return "oauth2_refresh_tokens" }

func toCoreRefreshToken(gr *gormRefreshToken) *oauth2.RefreshToken {
	if gr == nil {
		return nil
	}
	return &oauth2.RefreshToken{
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
