package kgorm

import (
	"context"

	"github.com/getkayan/kayan/core/oauth2"
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
