package rbac

import "context"

// RBACStorage defines the interface for persisting roles and permissions.
// In a simple setup, roles are stored directly in the identity traits/roles field.
// This interface allows for more complex external storage if needed.
type RBACStorage interface {
	GetIdentityRoles(ctx context.Context, identityID any) ([]string, error)
	SetIdentityRoles(ctx context.Context, identityID any, roles []string) error
}
