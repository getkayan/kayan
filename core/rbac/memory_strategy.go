package rbac

import (
	"fmt"
	"sync"
)

// Role represents a named role with a set of permissions.
type Role struct {
	Name        string
	Permissions []string
}

// MemoryStrategy is a built-in RBAC strategy backed by in-memory maps.
// It stores role definitions and identity-to-role assignments, suitable for
// testing, small deployments, or as a reference implementation.
type MemoryStrategy struct {
	mu          sync.RWMutex
	roles       map[string]*Role
	assignments map[string]map[string]bool // fmt.Sprint(identityID) → set of role names
}

// NewMemoryStrategy creates a new in-memory RBAC strategy.
func NewMemoryStrategy() *MemoryStrategy {
	return &MemoryStrategy{
		roles:       make(map[string]*Role),
		assignments: make(map[string]map[string]bool),
	}
}

// AddRole registers a role definition.
func (s *MemoryStrategy) AddRole(role *Role) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.roles[role.Name] = role
}

// AssignRole assigns a role to an identity. Returns error if role is not defined.
func (s *MemoryStrategy) AssignRole(identityID any, role string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.roles[role]; !ok {
		return fmt.Errorf("rbac: role %q not defined", role)
	}
	key := fmt.Sprintf("%v", identityID)
	if s.assignments[key] == nil {
		s.assignments[key] = make(map[string]bool)
	}
	s.assignments[key][role] = true
	return nil
}

// UnassignRole removes a role from an identity.
func (s *MemoryStrategy) UnassignRole(identityID any, role string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	key := fmt.Sprintf("%v", identityID)
	delete(s.assignments[key], role)
}

func (s *MemoryStrategy) HasRole(identityID any, role string) (bool, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	key := fmt.Sprintf("%v", identityID)
	return s.assignments[key][role], nil
}

func (s *MemoryStrategy) GetRoles(identityID any) ([]string, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	key := fmt.Sprintf("%v", identityID)
	roleSet := s.assignments[key]
	roles := make([]string, 0, len(roleSet))
	for r := range roleSet {
		roles = append(roles, r)
	}
	return roles, nil
}

func (s *MemoryStrategy) HasPermission(identityID any, permission string) (bool, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	key := fmt.Sprintf("%v", identityID)
	for roleName := range s.assignments[key] {
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

func (s *MemoryStrategy) GetPermissions(identityID any) ([]string, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	key := fmt.Sprintf("%v", identityID)
	seen := make(map[string]bool)
	var perms []string
	for roleName := range s.assignments[key] {
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
