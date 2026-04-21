package rbac

import (
	"context"
	"fmt"
)

// Strategy defines the interface for authorization checks.
type Strategy interface {
	HasRole(identityID any, role string) (bool, error)
	GetRoles(identityID any) ([]string, error)
	HasPermission(identityID any, permission string) (bool, error)
	GetPermissions(identityID any) ([]string, error)
}

// RoleSource is an interface for objects that can provide their own roles.
// This allows for optimization where roles are already loaded.
type RoleSource interface {
	GetRoles() []string
}

// PermissionSource is an interface for objects that can provide their own permissions.
type PermissionSource interface {
	GetPermissions() []string
}

// IdentityLoader loads an identity or subject object by ID.
type IdentityLoader func(identityID any) (any, error)

// BasicStrategy implements RBAC by reading roles and permissions from local interfaces.
// It can optionally load a subject object when only an identity ID is available.
type BasicStrategy struct {
	loader IdentityLoader
}

func NewBasicStrategy(loader IdentityLoader) *BasicStrategy {
	return &BasicStrategy{loader: loader}
}

func (s *BasicStrategy) GetRoles(identityID any) ([]string, error) {
	if rs, ok := identityID.(RoleSource); ok {
		return rs.GetRoles(), nil
	}

	ident, err := s.load(identityID)
	if err != nil {
		return nil, err
	}

	rs, ok := ident.(RoleSource)
	if !ok {
		return nil, fmt.Errorf("rbac: identity does not implement RoleSource")
	}

	return rs.GetRoles(), nil
}

func (s *BasicStrategy) HasRole(identityID any, role string) (bool, error) {
	roles, err := s.GetRoles(identityID)
	if err != nil {
		return false, err
	}

	for _, r := range roles {
		if r == role {
			return true, nil
		}
	}

	return false, nil
}

func (s *BasicStrategy) GetPermissions(identityID any) ([]string, error) {
	if ps, ok := identityID.(PermissionSource); ok {
		return ps.GetPermissions(), nil
	}

	ident, err := s.load(identityID)
	if err != nil {
		return nil, err
	}

	ps, ok := ident.(PermissionSource)
	if !ok {
		return nil, fmt.Errorf("rbac: identity does not implement PermissionSource")
	}

	return ps.GetPermissions(), nil
}

func (s *BasicStrategy) HasPermission(identityID any, permission string) (bool, error) {
	perms, err := s.GetPermissions(identityID)
	if err != nil {
		return false, err
	}

	for _, p := range perms {
		if p == permission {
			return true, nil
		}
	}

	return false, nil
}

// Can implements policy.Engine interface for unified authorization.
// The 'action' parameter is interpreted as the required role.
// The 'resource' parameter is ignored for basic RBAC.
// Example: Can(ctx, identityID, "admin", nil) checks if identity has "admin" role.
func (s *BasicStrategy) Can(ctx context.Context, subject any, action string, resource any) (bool, error) {
	return s.HasRole(subject, action)
}

func (s *BasicStrategy) load(identityID any) (any, error) {
	if s.loader == nil {
		return nil, fmt.Errorf("rbac: loader is nil and identity does not implement the required interfaces")
	}

	ident, err := s.loader(identityID)
	if err != nil {
		return nil, err
	}
	if ident == nil {
		return nil, fmt.Errorf("rbac: identity not found")
	}

	return ident, nil
}
