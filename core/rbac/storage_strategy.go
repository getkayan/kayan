package rbac

import (
	"context"
	"fmt"
)

// StorageStrategy is an RBAC strategy backed by persistent storage.
//
// Both halves of the model live in storage: identity-to-role assignments and
// the role definitions themselves. Holding definitions in process memory —
// as this type previously did — means a role created on one replica is unknown
// to every other, and a permission check there returns false with no error.
// A silent wrong denial in a permission system is worse than a loud failure,
// because nothing reports it and the behavior depends on which replica served
// the request.
type StorageStrategy struct {
	assignments RBACStorage
	roles       RoleStore
}

var _ Strategy = (*StorageStrategy)(nil)

// NewStorageStrategy returns a strategy reading assignments and role
// definitions from storage.
func NewStorageStrategy(assignments RBACStorage, roles RoleStore) *StorageStrategy {
	return &StorageStrategy{assignments: assignments, roles: roles}
}

// DefineRole creates or replaces a role definition.
func (s *StorageStrategy) DefineRole(ctx context.Context, role *Role) error {
	if role == nil || role.Name == "" {
		return fmt.Errorf("rbac: role must have a name")
	}

	// Reject a definition that would create a cycle at write time rather than
	// at check time, so the failure lands on whoever introduced it.
	previous, previousErr := s.roles.GetRole(ctx, role.Name)

	if err := s.roles.SaveRole(ctx, role); err != nil {
		return fmt.Errorf("rbac: save role %q: %w", role.Name, err)
	}

	if _, err := resolvePermissions(ctx, s.roles, role.Name, map[string]bool{}, 0); err != nil {
		// Put back what was there. Deleting instead would turn a bad edit into
		// an outage for every identity holding the role.
		if previousErr == nil {
			_ = s.roles.SaveRole(ctx, previous)
		} else {
			_ = s.roles.DeleteRole(ctx, role.Name)
		}
		return err
	}
	return nil
}

// DeleteRole removes a role definition.
func (s *StorageStrategy) DeleteRole(ctx context.Context, name string) error {
	return s.roles.DeleteRole(ctx, name)
}

// HasRole implements [Strategy].
func (s *StorageStrategy) HasRole(ctx context.Context, identityID any, role string) (bool, error) {
	assigned, err := s.assignments.GetIdentityRoles(ctx, identityID)
	if err != nil {
		return false, fmt.Errorf("rbac: read roles: %w", err)
	}

	for _, name := range assigned {
		if name == role {
			return true, nil
		}
	}
	return false, nil
}

// GetRoles implements [Strategy].
func (s *StorageStrategy) GetRoles(ctx context.Context, identityID any) ([]string, error) {
	roles, err := s.assignments.GetIdentityRoles(ctx, identityID)
	if err != nil {
		return nil, fmt.Errorf("rbac: read roles: %w", err)
	}
	return roles, nil
}

// HasPermission implements [Strategy].
//
// Permissions are matched with [PermissionGranted], so a role granted
// "users:*" satisfies a check for "users:delete".
func (s *StorageStrategy) HasPermission(ctx context.Context, identityID any, permission string) (bool, error) {
	permissions, err := s.GetPermissions(ctx, identityID)
	if err != nil {
		return false, err
	}
	return AnyPermissionGranted(permissions, permission), nil
}

// GetPermissions implements [Strategy].
//
// The result includes permissions inherited from parent roles.
func (s *StorageStrategy) GetPermissions(ctx context.Context, identityID any) ([]string, error) {
	assigned, err := s.assignments.GetIdentityRoles(ctx, identityID)
	if err != nil {
		return nil, fmt.Errorf("rbac: read roles: %w", err)
	}

	var permissions []string
	for _, name := range assigned {
		resolved, err := resolvePermissions(ctx, s.roles, name, map[string]bool{}, 0)
		if err != nil {
			// An assignment naming an undefined role is a broken
			// configuration. Reporting it beats silently dropping the role and
			// denying access for a reason nobody can see.
			return nil, fmt.Errorf("rbac: identity holds role %q: %w", name, err)
		}
		permissions = append(permissions, resolved...)
	}
	return dedupe(permissions), nil
}
