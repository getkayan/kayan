package rbac

import (
	"fmt"
)

// Manager handles authorization checks using a configured strategy.
type Manager struct {
	strategy Strategy
}

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
