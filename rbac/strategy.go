package rbac

import (
	"encoding/json"
	"fmt"

	"github.com/getkayan/kayan/domain"
	"github.com/getkayan/kayan/identity"
)

// Strategy defines the interface for authorization checks.
type Strategy interface {
	HasRole(identityID any, role string) (bool, error)
	GetRoles(identityID any) ([]string, error)
	HasPermission(identityID any, permission string) (bool, error)
	GetPermissions(identityID any) ([]string, error)
}

// BasicStrategy implements RBAC by reading roles directly from the Identity model.
// It uses the provided IdentityStorage to fetch the identity.
type BasicStrategy struct {
	storage domain.IdentityStorage
}

func NewBasicStrategy(storage domain.IdentityStorage) *BasicStrategy {
	return &BasicStrategy{storage: storage}
}

func (s *BasicStrategy) GetRoles(identityID any) ([]string, error) {
	// For BasicStrategy, we assume the identity model has a Roles field
	// which is a JSON array of strings.
	ident, err := s.storage.GetIdentity(func() any { return &identity.Identity{} }, identityID)
	if err != nil {
		return nil, err
	}

	i, ok := ident.(*identity.Identity)
	if !ok {
		return nil, fmt.Errorf("invalid identity type")
	}

	if len(i.Roles) == 0 {
		return []string{}, nil
	}

	var roles []string
	if err := json.Unmarshal(i.Roles, &roles); err != nil {
		return nil, fmt.Errorf("failed to parse roles: %v", err)
	}

	return roles, nil
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
	ident, err := s.storage.GetIdentity(func() any { return &identity.Identity{} }, identityID)
	if err != nil {
		return nil, err
	}

	i, ok := ident.(*identity.Identity)
	if !ok {
		return nil, fmt.Errorf("invalid identity type")
	}

	if len(i.Permissions) == 0 {
		return []string{}, nil
	}

	var perms []string
	if err := json.Unmarshal(i.Permissions, &perms); err != nil {
		return nil, fmt.Errorf("failed to parse permissions: %v", err)
	}

	return perms, nil
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
