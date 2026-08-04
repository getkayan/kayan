package rbac

import (
	"context"
	"fmt"
	"sync"
)

// MemoryStrategy is an RBAC strategy holding roles and assignments in memory.
//
// It is correct for a single process. Several replicas each keep their own
// copy, so a role defined on one is unknown to the others — use
// [StorageStrategy] with a shared [RoleStore] for anything running more than
// one instance.
type MemoryStrategy struct {
	mu          sync.RWMutex
	roles       map[string]*Role
	assignments map[string]map[string]bool // fmt.Sprint(identityID) → role names
}

var (
	_ Strategy  = (*MemoryStrategy)(nil)
	_ RoleStore = (*MemoryStrategy)(nil)
)

// NewMemoryStrategy returns an empty in-memory RBAC strategy.
func NewMemoryStrategy() *MemoryStrategy {
	return &MemoryStrategy{
		roles:       make(map[string]*Role),
		assignments: make(map[string]map[string]bool),
	}
}

// --- RoleStore ---

// GetRole implements [RoleStore].
func (s *MemoryStrategy) GetRole(_ context.Context, name string) (*Role, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	role, ok := s.roles[name]
	if !ok {
		return nil, fmt.Errorf("%w: %q", ErrRoleNotFound, name)
	}
	return role, nil
}

// SaveRole implements [RoleStore].
func (s *MemoryStrategy) SaveRole(_ context.Context, role *Role) error {
	if role == nil || role.Name == "" {
		return fmt.Errorf("rbac: role must have a name")
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	s.roles[role.Name] = role
	return nil
}

// DeleteRole implements [RoleStore].
func (s *MemoryStrategy) DeleteRole(_ context.Context, name string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.roles, name)
	return nil
}

// ListRoles implements [RoleStore].
func (s *MemoryStrategy) ListRoles(_ context.Context) ([]*Role, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	roles := make([]*Role, 0, len(s.roles))
	for _, role := range s.roles {
		roles = append(roles, role)
	}
	return roles, nil
}

// DefineRole registers a role definition.
//
// It rejects a definition that would introduce an inheritance cycle or name an
// undefined parent, so the failure lands on whoever wrote it rather than on a
// later permission check.
//
// A rejected definition leaves the previous one in place. Removing it instead
// would turn a bad edit into an outage: every identity holding that role would
// start failing permission checks.
func (s *MemoryStrategy) DefineRole(role *Role) error {
	ctx := context.Background()

	previous, hadPrevious := s.snapshotRole(role.Name)

	if err := s.SaveRole(ctx, role); err != nil {
		return err
	}
	if _, err := resolvePermissions(ctx, s, role.Name, map[string]bool{}, 0); err != nil {
		s.restoreRole(role.Name, previous, hadPrevious)
		return err
	}
	return nil
}

// snapshotRole returns the current definition of a role, if any.
func (s *MemoryStrategy) snapshotRole(name string) (*Role, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	role, ok := s.roles[name]
	return role, ok
}

// restoreRole puts back a previous definition, or removes the name entirely
// when there was none.
func (s *MemoryStrategy) restoreRole(name string, previous *Role, hadPrevious bool) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if hadPrevious {
		s.roles[name] = previous
		return
	}
	delete(s.roles, name)
}

// --- assignments ---

// AddRole registers a role definition without validating inheritance.
//
// Prefer [MemoryStrategy.DefineRole], which rejects a definition that would
// introduce a cycle.
func (s *MemoryStrategy) AddRole(role *Role) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.roles[role.Name] = role
}

// AssignRole grants a role to an identity.
//
// It reports an error when the role has no definition, so a typo surfaces
// where it was made rather than as an unexplained denial later.
func (s *MemoryStrategy) AssignRole(identityID any, role string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, ok := s.roles[role]; !ok {
		return fmt.Errorf("%w: %q", ErrRoleNotFound, role)
	}

	key := fmt.Sprint(identityID)
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
	delete(s.assignments[fmt.Sprint(identityID)], role)
}

// RevokeRole removes a role from an identity.
//
// Deprecated: use [MemoryStrategy.UnassignRole], the name the rest of the
// package uses.
func (s *MemoryStrategy) RevokeRole(identityID any, role string) {
	s.UnassignRole(identityID, role)
}

// --- Strategy ---

// HasRole implements [Strategy].
func (s *MemoryStrategy) HasRole(_ context.Context, identityID any, role string) (bool, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	return s.assignments[fmt.Sprint(identityID)][role], nil
}

// GetRoles implements [Strategy].
func (s *MemoryStrategy) GetRoles(_ context.Context, identityID any) ([]string, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	assigned := s.assignments[fmt.Sprint(identityID)]
	roles := make([]string, 0, len(assigned))
	for role := range assigned {
		roles = append(roles, role)
	}
	return roles, nil
}

// HasPermission implements [Strategy].
//
// Matching is by [PermissionGranted], so a role granted "users:*" satisfies a
// check for "users:delete".
func (s *MemoryStrategy) HasPermission(ctx context.Context, identityID any, permission string) (bool, error) {
	permissions, err := s.GetPermissions(ctx, identityID)
	if err != nil {
		return false, err
	}
	return AnyPermissionGranted(permissions, permission), nil
}

// GetPermissions implements [Strategy], including inherited permissions.
func (s *MemoryStrategy) GetPermissions(ctx context.Context, identityID any) ([]string, error) {
	roles, err := s.GetRoles(ctx, identityID)
	if err != nil {
		return nil, err
	}

	var permissions []string
	for _, name := range roles {
		resolved, err := resolvePermissions(ctx, s, name, map[string]bool{}, 0)
		if err != nil {
			return nil, fmt.Errorf("rbac: identity holds role %q: %w", name, err)
		}
		permissions = append(permissions, resolved...)
	}
	return dedupe(permissions), nil
}
