package gormstore

import (
	"context"
	"errors"
	"fmt"

	"github.com/getkayan/kayan/core/rbac"
	"gorm.io/gorm"
)

// RoleAssignment represents an identity-to-role mapping for RBAC.
type RoleAssignment struct {
	ID         uint   `gorm:"primaryKey;autoIncrement"`
	TenantId   string `gorm:"column:tenant_id;index"`
	IdentityID string `gorm:"index:idx_role_identity;not null"`
	Role       string `gorm:"index:idx_role_identity;not null"`
}

func (RoleAssignment) TableName() string { return "role_assignments" }

func (a *RoleAssignment) TenantID() string      { return a.TenantId }
func (a *RoleAssignment) SetTenantID(id string) { a.TenantId = id }

// RoleDefinition is the persisted form of a role.
//
// Definitions live in storage rather than in process memory because they are
// shared state: a role created on one replica must be visible to the next
// request, whichever replica serves it. Holding them per process meant a
// permission check on another replica returned false with no error, which is
// indistinguishable from a legitimate denial.
type RoleDefinition struct {
	Name        string   `gorm:"primaryKey"`
	TenantId    string   `gorm:"column:tenant_id;primaryKey"`
	Permissions []string `gorm:"type:text;serializer:json"`
	Inherits    []string `gorm:"type:text;serializer:json"`
	Description string
}

func (RoleDefinition) TableName() string { return "role_definitions" }

func (d *RoleDefinition) TenantID() string      { return d.TenantId }
func (d *RoleDefinition) SetTenantID(id string) { d.TenantId = id }

// RBACRepository persists role assignments and role definitions.
type RBACRepository struct {
	db *gorm.DB
}

// Compile-time proof that this repository satisfies both halves of the RBAC
// model. Without these, a signature drift shows up as a caller that will not
// compile rather than here, where it is fixable.
var (
	_ rbac.RBACStorage = (*RBACRepository)(nil)
	_ rbac.RoleStore   = (*RBACRepository)(nil)
)

// NewRBACRepository creates a new GORM-backed RBAC repository.
//
// It provides both the assignment store and the role store that
// [rbac.NewStorageStrategy] requires:
//
//	repo := gormstore.NewRBACRepository(db)
//	strategy := rbac.NewStorageStrategy(repo, repo)
func NewRBACRepository(db *gorm.DB) *RBACRepository {
	return &RBACRepository{db: db}
}

// AutoMigrate creates the tables this repository needs.
//
// For development only; production applies the versioned SQL from
// [Migrations].
func (r *RBACRepository) AutoMigrate() error {
	return r.db.AutoMigrate(&RoleAssignment{}, &RoleDefinition{})
}

// --- assignments ---

// GetIdentityRoles returns all role names assigned to an identity.
func (r *RBACRepository) GetIdentityRoles(ctx context.Context, identityID any) ([]string, error) {
	id := fmt.Sprintf("%v", identityID)

	var assignments []RoleAssignment
	if err := r.db.WithContext(ctx).Where("identity_id = ?", id).Find(&assignments).Error; err != nil {
		return nil, fmt.Errorf("gormstore: get identity roles: %w", err)
	}

	roles := make([]string, len(assignments))
	for i, a := range assignments {
		roles[i] = a.Role
	}
	return roles, nil
}

// SetIdentityRoles replaces all roles for an identity in a single transaction.
//
// Replacing rather than merging is what makes revocation work: a role absent
// from the new set is removed, and doing it in one transaction means a
// concurrent read never sees an identity with no roles at all.
func (r *RBACRepository) SetIdentityRoles(ctx context.Context, identityID any, roles []string) error {
	id := fmt.Sprintf("%v", identityID)

	return r.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if err := tx.Where("identity_id = ?", id).Delete(&RoleAssignment{}).Error; err != nil {
			return fmt.Errorf("gormstore: delete old roles: %w", err)
		}
		for _, role := range roles {
			assignment := RoleAssignment{IdentityID: id, Role: role}
			if err := tx.Create(&assignment).Error; err != nil {
				return fmt.Errorf("gormstore: assign role %q: %w", role, err)
			}
		}
		return nil
	})
}

// --- definitions ---

// GetRole implements [rbac.RoleStore].
//
// A missing definition returns [rbac.ErrRoleNotFound] rather than an empty
// role. An identity assigned a role with no definition is a broken
// configuration, and reporting it beats resolving to no permissions — which
// looks exactly like a legitimate denial.
func (r *RBACRepository) GetRole(ctx context.Context, name string) (*rbac.Role, error) {
	var model RoleDefinition
	err := r.db.WithContext(ctx).First(&model, "name = ?", name).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, fmt.Errorf("%w: %q", rbac.ErrRoleNotFound, name)
	}
	if err != nil {
		return nil, fmt.Errorf("gormstore: get role %q: %w", name, err)
	}

	return &rbac.Role{
		Name:        model.Name,
		Permissions: model.Permissions,
		Inherits:    model.Inherits,
		Description: model.Description,
	}, nil
}

// SaveRole implements [rbac.RoleStore], creating or replacing a definition.
func (r *RBACRepository) SaveRole(ctx context.Context, role *rbac.Role) error {
	if role == nil || role.Name == "" {
		return errors.New("gormstore: role must have a name")
	}

	model := &RoleDefinition{
		Name:        role.Name,
		Permissions: role.Permissions,
		Inherits:    role.Inherits,
		Description: role.Description,
	}
	if err := r.db.WithContext(ctx).Save(model).Error; err != nil {
		return fmt.Errorf("gormstore: save role %q: %w", role.Name, err)
	}
	return nil
}

// DeleteRole implements [rbac.RoleStore].
//
// Assignments naming the deleted role are left in place. They will report
// [rbac.ErrRoleNotFound] on the next permission check, which surfaces the
// broken configuration rather than silently stripping a user's access.
func (r *RBACRepository) DeleteRole(ctx context.Context, name string) error {
	return r.db.WithContext(ctx).Delete(&RoleDefinition{}, "name = ?", name).Error
}

// ListRoles implements [rbac.RoleStore].
func (r *RBACRepository) ListRoles(ctx context.Context) ([]*rbac.Role, error) {
	var models []RoleDefinition
	if err := r.db.WithContext(ctx).Find(&models).Error; err != nil {
		return nil, fmt.Errorf("gormstore: list roles: %w", err)
	}

	roles := make([]*rbac.Role, 0, len(models))
	for _, model := range models {
		roles = append(roles, &rbac.Role{
			Name:        model.Name,
			Permissions: model.Permissions,
			Inherits:    model.Inherits,
			Description: model.Description,
		})
	}
	return roles, nil
}
