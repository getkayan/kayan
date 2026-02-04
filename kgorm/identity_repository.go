package kgorm

import (
	"context"

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

func (r *IdentityRepository) CreateIdentity(ident any) error {
	return r.db.Create(ident).Error
}

func (r *IdentityRepository) CreateCredential(cred any) error {
	// Convert to gormCredential if it's identity.Credential
	if c, ok := cred.(*identity.Credential); ok {
		gc := fromCoreCredential(c)
		return r.db.Create(gc).Error
	}
	return r.db.Create(cred).Error
}

func (r *IdentityRepository) GetIdentity(factory func() any, id any) (any, error) {
	ident := factory()
	if err := r.db.First(ident, "id = ?", id).Error; err != nil {
		return nil, err
	}
	return ident, nil
}

func (r *IdentityRepository) FindIdentity(factory func() any, query map[string]any) (any, error) {
	ident := factory()
	if err := r.db.Where(query).First(ident).Error; err != nil {
		return nil, err
	}
	return ident, nil
}

func (r *IdentityRepository) ListIdentities(factory func() any, page, limit int) ([]any, error) {
	// Create a slice to hold results
	results := make([]any, 0)
	offset := (page - 1) * limit
	if offset < 0 {
		offset = 0
	}

	// We need to query and scan into a slice
	// This is tricky with GORM and generics, so we use raw approach
	rows, err := r.db.Model(factory()).Offset(offset).Limit(limit).Rows()
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	for rows.Next() {
		ident := factory()
		if err := r.db.ScanRows(rows, ident); err != nil {
			return nil, err
		}
		results = append(results, ident)
	}
	return results, nil
}

func (r *IdentityRepository) UpdateIdentity(ident any) error {
	// Convert to gormIdentity if it's identity.Identity
	if i, ok := ident.(*identity.Identity); ok {
		gi := fromCoreIdentity(i)
		return r.db.Save(gi).Error
	}
	// Fallback to generic save
	return r.db.Save(ident).Error
}

func (r *IdentityRepository) DeleteIdentity(id any) error {
	return r.db.Delete(&gormIdentity{}, "id = ?", id).Error
}

func (r *IdentityRepository) GetCredentialByIdentifier(identifier string, method string) (*identity.Credential, error) {
	var cred gormCredential
	query := r.db.Where("identifier = ?", identifier)
	if method != "" {
		query = query.Where("type = ?", method)
	}

	if err := query.First(&cred).Error; err != nil {
		return nil, err
	}

	return toCoreCredential(&cred), nil
}

func (r *IdentityRepository) UpdateCredentialSecret(ctx context.Context, identityID, method, secret string) error {
	return r.db.WithContext(ctx).Model(&gormCredential{}).
		Where("identity_id = ? AND type = ?", identityID, method).
		Update("secret", secret).Error
}
