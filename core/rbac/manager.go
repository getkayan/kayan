// Package rbac provides Role-Based Access Control for Kayan IAM.
//
// The rbac package implements a flexible RBAC system with support for:
//
//   - Role assignment and checking
//   - Permission-based authorization
//   - Hierarchical roles (through custom strategies)
//   - Pluggable storage backends
//
// # Basic Usage
//
//	// Setup
//	strategy := rbac.NewGORMStrategy(db)
//	manager := rbac.NewManager(strategy)
//
//	// Assign roles
//	strategy.AssignRole(userID, "admin")
//
//	// Check authorization
//	allowed, err := manager.Authorize(userID, "admin")
//	if allowed {
//	    // User has admin role
//	}
//
// # Permissions
//
// Roles can have associated permissions for fine-grained control:
//
//	// Check specific permission
//	allowed, err := manager.AuthorizePermission(userID, "users:delete")
//
//	// Get all permissions for a user
//	perms, err := manager.GetPermissions(userID)
//
// # Headless Integration
//
// The rbac package stays transport-agnostic. Use Manager methods from your own
// HTTP or RPC adapter layer instead of importing framework middleware from core.
//
// See also: policy package for ABAC, rebac package for relationship-based access.
package rbac

import (
	"context"
	"fmt"
)

// Manager handles authorization checks using a configured strategy.
// It provides a high-level API for role and permission checks.
type Manager struct {
	strategy Strategy
}

// NewManager creates a new RBAC Manager with the given strategy.
func NewManager(strategy Strategy) *Manager {
	return &Manager{strategy: strategy}
}

// Authorize checks if the given identity has the required role.
func (m *Manager) Authorize(ctx context.Context, identityID any, role string) (bool, error) {
	if m.strategy == nil {
		return false, fmt.Errorf("rbac strategy not configured")
	}
	return m.strategy.HasRole(ctx, identityID, role)
}

// GetRoles returns all roles for the given identity.
func (m *Manager) GetRoles(ctx context.Context, identityID any) ([]string, error) {
	if m.strategy == nil {
		return nil, fmt.Errorf("rbac strategy not configured")
	}
	return m.strategy.GetRoles(ctx, identityID)
}

// RequireRole is a helper that returns an error if the identity does not have the role.
func (m *Manager) RequireRole(ctx context.Context, identityID any, role string) error {
	allowed, err := m.Authorize(ctx, identityID, role)
	if err != nil {
		return err
	}
	if !allowed {
		return fmt.Errorf("access denied: missing role %s", role)
	}
	return nil
}

// AuthorizePermission checks if the given identity has the required permission.
func (m *Manager) AuthorizePermission(ctx context.Context, identityID any, permission string) (bool, error) {
	if m.strategy == nil {
		return false, fmt.Errorf("rbac strategy not configured")
	}
	return m.strategy.HasPermission(ctx, identityID, permission)
}

// GetPermissions returns all permissions for the given identity.
func (m *Manager) GetPermissions(ctx context.Context, identityID any) ([]string, error) {
	if m.strategy == nil {
		return nil, fmt.Errorf("rbac strategy not configured")
	}
	return m.strategy.GetPermissions(ctx, identityID)
}

// RequirePermission is a helper that returns an error if the identity does not have the permission.
func (m *Manager) RequirePermission(ctx context.Context, identityID any, permission string) error {
	allowed, err := m.AuthorizePermission(ctx, identityID, permission)
	if err != nil {
		return err
	}
	if !allowed {
		return fmt.Errorf("access denied: missing permission %s", permission)
	}
	return nil
}
