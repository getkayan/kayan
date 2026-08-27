package gormstore

import (
	"context"
	"fmt"

	"github.com/getkayan/kayan/core/domain"
	"github.com/getkayan/kayan/core/identity"
	"gorm.io/gorm"
)

// IdentityRepository handles identity and credential persistence.
type IdentityRepository struct {
	db *gorm.DB
}

// NewIdentityRepository creates a new IdentityRepository.
func NewIdentityRepository(db *gorm.DB) *IdentityRepository {
	return &IdentityRepository{db: db}
}

func (r *IdentityRepository) CreateIdentity(ctx context.Context, ident any) error {
	return storageError("create identity", r.db.WithContext(ctx).Create(ident).Error)
}

func (r *IdentityRepository) CreateCredential(ctx context.Context, cred any) error {
	// Convert to gormCredential if it's identity.Credential
	if c, ok := cred.(*identity.Credential); ok {
		gc := fromCoreCredential(c)
		return storageError("create credential", r.db.WithContext(ctx).Create(gc).Error)
	}
	return storageError("create credential", r.db.WithContext(ctx).Create(cred).Error)
}

func (r *IdentityRepository) GetIdentity(ctx context.Context, factory func() any, id any) (any, error) {
	ident := factory()
	if err := r.db.WithContext(ctx).First(ident, "id = ?", id).Error; err != nil {
		return nil, storageError("get identity", err)
	}
	return ident, nil
}

func (r *IdentityRepository) FindIdentity(ctx context.Context, factory func() any, query map[string]any) (any, error) {
	ident := factory()
	if err := r.db.WithContext(ctx).Where(query).First(ident).Error; err != nil {
		return nil, storageError("find identity", err)
	}
	return ident, nil
}

func (r *IdentityRepository) ListIdentities(ctx context.Context, factory func() any, page, limit int) ([]any, error) {
	// Create a slice to hold results
	results := make([]any, 0)
	offset := (page - 1) * limit
	if offset < 0 {
		offset = 0
	}

	// We need to query and scan into a slice
	// This is tricky with GORM and generics, so we use raw approach
	rows, err := r.db.WithContext(ctx).Model(factory()).Offset(offset).Limit(limit).Rows()
	if err != nil {
		return nil, storageError("list identities", err)
	}
	defer rows.Close()

	for rows.Next() {
		ident := factory()
		if err := r.db.WithContext(ctx).ScanRows(rows, ident); err != nil {
			return nil, storageError("scan identity", err)
		}
		results = append(results, ident)
	}
	return results, nil
}

func (r *IdentityRepository) UpdateIdentity(ctx context.Context, ident any) error {
	// Convert to gormIdentity if it's identity.Identity
	if i, ok := ident.(*identity.Identity); ok {
		gi := fromCoreIdentity(i)
		return storageError("update identity", r.db.WithContext(ctx).Save(gi).Error)
	}
	// Fallback to generic save
	return storageError("update identity", r.db.WithContext(ctx).Save(ident).Error)
}

func (r *IdentityRepository) DeleteIdentity(ctx context.Context, factory func() any, id any) error {
	return storageError("delete identity", r.db.WithContext(ctx).Delete(factory(), "id = ?", id).Error)
}

func (r *IdentityRepository) GetCredentialByIdentifier(ctx context.Context, identifier string, method string) (*identity.Credential, error) {
	var cred gormCredential
	query := r.db.WithContext(ctx).Where("identifier = ?", identifier)
	if method != "" {
		query = query.Where("type = ?", method)
	}

	if err := query.First(&cred).Error; err != nil {
		return nil, storageError("get credential", err)
	}

	return toCoreCredential(&cred), nil
}

func (r *IdentityRepository) UpdateCredentialSecret(ctx context.Context, identityID, method, secret string) error {
	result := r.db.WithContext(ctx).Model(&gormCredential{}).
		Where("identity_id = ? AND type = ?", identityID, method).
		Update("secret", secret)
	if result.Error != nil {
		return storageError("update credential", result.Error)
	}
	if result.RowsAffected == 0 {
		return fmt.Errorf("gormstore: update credential: %w", domain.ErrNotFound)
	}
	return nil
}
