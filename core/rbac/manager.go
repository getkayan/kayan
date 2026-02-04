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
// # Middleware
//
// Use the provided middleware for HTTP handlers:
//
//	e.GET("/admin", adminHandler, rbac.RequireRole(manager, "admin"))
//	e.DELETE("/users/:id", deleteHandler, rbac.RequirePermission(manager, "users:delete"))
//
// See also: policy package for ABAC, rebac package for relationship-based access.
package rbac

import (
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
func (m *Manager) Authorize(identityID any, role string) (bool, error) {
	if m.strategy == nil {
		return false, fmt.Errorf("rbac strategy not configured")
	}
	return m.strategy.HasRole(identityID, role)
}

// GetRoles returns all roles for the given identity.
func (m *Manager) GetRoles(identityID any) ([]string, error) {
	if m.strategy == nil {
		return nil, fmt.Errorf("rbac strategy not configured")
	}
	return m.strategy.GetRoles(identityID)
}

// RequireRole is a helper that returns an error if the identity does not have the role.
func (m *Manager) RequireRole(identityID any, role string) error {
	allowed, err := m.Authorize(identityID, role)
	if err != nil {
		return err
	}
	if !allowed {
		return fmt.Errorf("access denied: missing role %s", role)
	}
	return nil
}

// AuthorizePermission checks if the given identity has the required permission.
func (m *Manager) AuthorizePermission(identityID any, permission string) (bool, error) {
	if m.strategy == nil {
		return false, fmt.Errorf("rbac strategy not configured")
	}
	return m.strategy.HasPermission(identityID, permission)
}

// GetPermissions returns all permissions for the given identity.
func (m *Manager) GetPermissions(identityID any) ([]string, error) {
	if m.strategy == nil {
		return nil, fmt.Errorf("rbac strategy not configured")
	}
	return m.strategy.GetPermissions(identityID)
}

// RequirePermission is a helper that returns an error if the identity does not have the permission.
func (m *Manager) RequirePermission(identityID any, permission string) error {
	allowed, err := m.AuthorizePermission(identityID, permission)
	if err != nil {
		return err
	}
	if !allowed {
		return fmt.Errorf("access denied: missing permission %s", permission)
	}
	return nil
}
