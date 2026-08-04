package rbac

import (
	"context"
	"sync"
	"testing"
)

// sharedStore stands in for a database: several strategies read and write the
// same state, as replicas of one deployment do.
type sharedStore struct {
	mu          sync.RWMutex
	roles       map[string]*Role
	assignments map[string][]string
}

func newSharedStore() *sharedStore {
	return &sharedStore{
		roles:       make(map[string]*Role),
		assignments: make(map[string][]string),
	}
}

func (s *sharedStore) GetRole(_ context.Context, name string) (*Role, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	role, ok := s.roles[name]
	if !ok {
		return nil, ErrRoleNotFound
	}
	return role, nil
}

func (s *sharedStore) SaveRole(_ context.Context, role *Role) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.roles[role.Name] = role
	return nil
}

func (s *sharedStore) DeleteRole(_ context.Context, name string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.roles, name)
	return nil
}

func (s *sharedStore) ListRoles(_ context.Context) ([]*Role, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	roles := make([]*Role, 0, len(s.roles))
	for _, role := range s.roles {
		roles = append(roles, role)
	}
	return roles, nil
}

func (s *sharedStore) GetIdentityRoles(_ context.Context, identityID any) ([]string, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.assignments[key(identityID)], nil
}

func (s *sharedStore) SetIdentityRoles(_ context.Context, identityID any, roles []string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.assignments[key(identityID)] = roles
	return nil
}

func key(identityID any) string {
	if s, ok := identityID.(string); ok {
		return s
	}
	return ""
}

// TestRoleDefinedOnOneReplicaIsVisibleToAnother is the regression test for the
// bug this rewrite exists to fix.
//
// Role definitions used to be held in a process-local map while assignments
// lived in the database. A role created on one replica was unknown to every
// other, and a permission check there returned false with no error — a silent
// wrong denial whose behavior depended on which replica served the request.
func TestRoleDefinedOnOneReplicaIsVisibleToAnother(t *testing.T) {
	ctx := context.Background()
	store := newSharedStore()

	// Two strategies over the same storage, as two replicas would be.
	replicaOne := NewStorageStrategy(store, store)
	replicaTwo := NewStorageStrategy(store, store)

	// An administrator defines a role against whichever replica served them.
	if err := replicaOne.DefineRole(ctx, &Role{
		Name:        "editor",
		Permissions: []string{"docs:write"},
	}); err != nil {
		t.Fatalf("DefineRole: %v", err)
	}
	if err := store.SetIdentityRoles(ctx, "user-1", []string{"editor"}); err != nil {
		t.Fatalf("SetIdentityRoles: %v", err)
	}

	// The next request lands on the other replica.
	allowed, err := replicaTwo.HasPermission(ctx, "user-1", "docs:write")
	if err != nil {
		t.Fatalf("HasPermission on the second replica: %v", err)
	}
	if !allowed {
		t.Fatal("the second replica denied a permission granted by a role defined on the first")
	}
}

// TestReplicaSeesUpdatedRoleDefinition proves a changed definition takes
// effect everywhere, so revoking a permission actually revokes it.
func TestReplicaSeesUpdatedRoleDefinition(t *testing.T) {
	ctx := context.Background()
	store := newSharedStore()

	replicaOne := NewStorageStrategy(store, store)
	replicaTwo := NewStorageStrategy(store, store)

	if err := replicaOne.DefineRole(ctx, &Role{
		Name:        "editor",
		Permissions: []string{"docs:write", "docs:delete"},
	}); err != nil {
		t.Fatalf("DefineRole: %v", err)
	}
	if err := store.SetIdentityRoles(ctx, "user-1", []string{"editor"}); err != nil {
		t.Fatalf("SetIdentityRoles: %v", err)
	}

	allowed, err := replicaTwo.HasPermission(ctx, "user-1", "docs:delete")
	if err != nil {
		t.Fatalf("HasPermission: %v", err)
	}
	if !allowed {
		t.Fatal("the permission was not granted before the change")
	}

	// Narrow the role on one replica.
	if err := replicaOne.DefineRole(ctx, &Role{
		Name:        "editor",
		Permissions: []string{"docs:write"},
	}); err != nil {
		t.Fatalf("DefineRole: %v", err)
	}

	// The other replica must honor the revocation immediately.
	allowed, err = replicaTwo.HasPermission(ctx, "user-1", "docs:delete")
	if err != nil {
		t.Fatalf("HasPermission: %v", err)
	}
	if allowed {
		t.Fatal("a revoked permission is still granted on another replica")
	}
}

// TestStorageStrategyWildcardsAndInheritance proves the persisted path has the
// same semantics as the in-memory one.
func TestStorageStrategyWildcardsAndInheritance(t *testing.T) {
	ctx := context.Background()
	store := newSharedStore()
	strategy := NewStorageStrategy(store, store)

	if err := strategy.DefineRole(ctx, &Role{
		Name: "support", Permissions: []string{"tickets:*"},
	}); err != nil {
		t.Fatalf("DefineRole: %v", err)
	}
	if err := strategy.DefineRole(ctx, &Role{
		Name: "lead", Permissions: []string{"reports:read"}, Inherits: []string{"support"},
	}); err != nil {
		t.Fatalf("DefineRole: %v", err)
	}
	if err := store.SetIdentityRoles(ctx, "user-1", []string{"lead"}); err != nil {
		t.Fatalf("SetIdentityRoles: %v", err)
	}

	for _, permission := range []string{"tickets:close", "tickets:reassign", "reports:read"} {
		allowed, err := strategy.HasPermission(ctx, "user-1", permission)
		if err != nil {
			t.Fatalf("HasPermission %q: %v", permission, err)
		}
		if !allowed {
			t.Errorf("denied %q, which the role grants", permission)
		}
	}

	allowed, err := strategy.HasPermission(ctx, "user-1", "billing:read")
	if err != nil {
		t.Fatalf("HasPermission: %v", err)
	}
	if allowed {
		t.Error("granted a permission outside every assigned role")
	}
}

// TestUndefinedRoleFailsLoudlyInStorage proves the storage path reports a
// missing definition rather than denying silently.
func TestUndefinedRoleFailsLoudlyInStorage(t *testing.T) {
	ctx := context.Background()
	store := newSharedStore()
	strategy := NewStorageStrategy(store, store)

	if err := store.SetIdentityRoles(ctx, "user-1", []string{"never-defined"}); err != nil {
		t.Fatalf("SetIdentityRoles: %v", err)
	}

	if _, err := strategy.HasPermission(ctx, "user-1", "anything"); err == nil {
		t.Fatal("an assignment naming an undefined role was treated as no permissions")
	}
}
