package kgorm

import (
	"fmt"

	"gorm.io/gorm"
)

// RoleAssignment represents an identity-to-role mapping for RBAC.
type RoleAssignment struct {
	ID         uint   `gorm:"primaryKey;autoIncrement"`
	IdentityID string `gorm:"index:idx_role_identity;not null"`
	Role       string `gorm:"index:idx_role_identity;not null"`
}

func (RoleAssignment) TableName() string { return "role_assignments" }

// RBACRepository implements rbac.RBACStorage using GORM.
type RBACRepository struct {
	db *gorm.DB
}

// NewRBACRepository creates a new GORM-backed RBAC repository.
func NewRBACRepository(db *gorm.DB) *RBACRepository {
	return &RBACRepository{db: db}
}

// GetIdentityRoles returns all role names assigned to an identity.
func (r *RBACRepository) GetIdentityRoles(identityID any) ([]string, error) {
	id := fmt.Sprintf("%v", identityID)
	var assignments []RoleAssignment
	if err := r.db.Where("identity_id = ?", id).Find(&assignments).Error; err != nil {
		return nil, fmt.Errorf("kgorm: get identity roles: %w", err)
	}
	roles := make([]string, len(assignments))
	for i, a := range assignments {
		roles[i] = a.Role
	}
	return roles, nil
}

// SetIdentityRoles replaces all roles for an identity in a single transaction.
func (r *RBACRepository) SetIdentityRoles(identityID any, roles []string) error {
	id := fmt.Sprintf("%v", identityID)
	return r.db.Transaction(func(tx *gorm.DB) error {
		if err := tx.Where("identity_id = ?", id).Delete(&RoleAssignment{}).Error; err != nil {
			return fmt.Errorf("kgorm: delete old roles: %w", err)
		}
		for _, role := range roles {
			a := RoleAssignment{IdentityID: id, Role: role}
			if err := tx.Create(&a).Error; err != nil {
				return fmt.Errorf("kgorm: assign role %q: %w", role, err)
			}
		}
		return nil
	})
}
