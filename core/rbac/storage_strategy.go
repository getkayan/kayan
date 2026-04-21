package rbac

import (
	"fmt"
	"sync"
)

// StorageStrategy is an RBAC strategy backed by a persistent RBACStorage.
// Role definitions (name → permissions) are held in memory, while identity-to-role
// assignments are delegated to the storage backend.
type StorageStrategy struct {
	store RBACStorage
	mu    sync.RWMutex
	roles map[string]*Role
}

// NewStorageStrategy creates a new storage-backed RBAC strategy.
func NewStorageStrategy(store RBACStorage) *StorageStrategy {
	return &StorageStrategy{
		store: store,
		roles: make(map[string]*Role),
	}
}

// DefineRole registers a role definition with its permissions.
func (s *StorageStrategy) DefineRole(role *Role) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.roles[role.Name] = role
}

func (s *StorageStrategy) HasRole(identityID any, role string) (bool, error) {
	roles, err := s.store.GetIdentityRoles(identityID)
	if err != nil {
		return false, fmt.Errorf("rbac: storage: %w", err)
	}
	for _, r := range roles {
		if r == role {
			return true, nil
		}
	}
	return false, nil
}

func (s *StorageStrategy) GetRoles(identityID any) ([]string, error) {
	roles, err := s.store.GetIdentityRoles(identityID)
	if err != nil {
		return nil, fmt.Errorf("rbac: storage: %w", err)
	}
	return roles, nil
}

func (s *StorageStrategy) HasPermission(identityID any, permission string) (bool, error) {
	roles, err := s.store.GetIdentityRoles(identityID)
	if err != nil {
		return false, fmt.Errorf("rbac: storage: %w", err)
	}

	s.mu.RLock()
	defer s.mu.RUnlock()

	for _, roleName := range roles {
		role := s.roles[roleName]
		if role == nil {
			continue
		}
		for _, p := range role.Permissions {
			if p == permission {
				return true, nil
			}
		}
	}
	return false, nil
}

func (s *StorageStrategy) GetPermissions(identityID any) ([]string, error) {
	roles, err := s.store.GetIdentityRoles(identityID)
	if err != nil {
		return nil, fmt.Errorf("rbac: storage: %w", err)
	}

	s.mu.RLock()
	defer s.mu.RUnlock()

	seen := make(map[string]bool)
	var perms []string
	for _, roleName := range roles {
		role := s.roles[roleName]
		if role == nil {
			continue
		}
		for _, p := range role.Permissions {
			if !seen[p] {
				seen[p] = true
				perms = append(perms, p)
			}
		}
	}
	return perms, nil
}
