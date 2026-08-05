package gormstore

import (
	"context"
	"errors"
	"testing"

	"github.com/getkayan/kayan/core/rbac"
	"github.com/glebarez/sqlite"
	"gorm.io/gorm"
)

func newRBACRepo(t *testing.T) *RBACRepository {
	t.Helper()

	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	repo := NewRBACRepository(db)
	if err := repo.AutoMigrate(); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	return repo
}

// TestRepositoryIsWireableIntoStorageStrategy is the regression test for a
// real gap: RBACRepository documented itself as implementing rbac.RBACStorage
// while its methods took no context, so it could not be passed to
// NewStorageStrategy at all. Nothing caught it, because nothing asserted
// conformance and no test wired the two together.
//
// With no RoleStore implementation shipping either, multi-replica RBAC had no
// persistent path that could actually be constructed.
func TestRepositoryIsWireableIntoStorageStrategy(t *testing.T) {
	ctx := context.Background()
	repo := newRBACRepo(t)

	strategy := rbac.NewStorageStrategy(repo, repo)

	if err := strategy.DefineRole(ctx, &rbac.Role{
		Name:        "editor",
		Permissions: []string{"docs:write"},
	}); err != nil {
		t.Fatalf("DefineRole: %v", err)
	}
	if err := repo.SetIdentityRoles(ctx, "user-1", []string{"editor"}); err != nil {
		t.Fatalf("SetIdentityRoles: %v", err)
	}

	allowed, err := strategy.HasPermission(ctx, "user-1", "docs:write")
	if err != nil {
		t.Fatalf("HasPermission: %v", err)
	}
	if !allowed {
		t.Fatal("a permission granted by an assigned role was denied")
	}
}

// TestDefinitionsAreSharedAcrossReplicas is the property that made persisting
// definitions necessary. Two strategies over one database stand in for two
// replicas of a deployment.
func TestDefinitionsAreSharedAcrossReplicas(t *testing.T) {
	ctx := context.Background()
	repo := newRBACRepo(t)

	replicaOne := rbac.NewStorageStrategy(repo, repo)
	replicaTwo := rbac.NewStorageStrategy(repo, repo)

	if err := replicaOne.DefineRole(ctx, &rbac.Role{
		Name:        "support",
		Permissions: []string{"tickets:*"},
	}); err != nil {
		t.Fatalf("DefineRole: %v", err)
	}
	if err := repo.SetIdentityRoles(ctx, "user-1", []string{"support"}); err != nil {
		t.Fatalf("SetIdentityRoles: %v", err)
	}

	// The next request lands on the other replica.
	allowed, err := replicaTwo.HasPermission(ctx, "user-1", "tickets:close")
	if err != nil {
		t.Fatalf("HasPermission on the second replica: %v", err)
	}
	if !allowed {
		t.Fatal("the second replica denied a permission the first granted")
	}
}

// TestInheritanceResolvesFromStorage proves parent roles are followed when the
// definitions come from the database rather than from memory.
func TestInheritanceResolvesFromStorage(t *testing.T) {
	ctx := context.Background()
	repo := newRBACRepo(t)
	strategy := rbac.NewStorageStrategy(repo, repo)

	for _, role := range []*rbac.Role{
		{Name: "viewer", Permissions: []string{"docs:read"}},
		{Name: "editor", Permissions: []string{"docs:write"}, Inherits: []string{"viewer"}},
	} {
		if err := strategy.DefineRole(ctx, role); err != nil {
			t.Fatalf("DefineRole %s: %v", role.Name, err)
		}
	}
	if err := repo.SetIdentityRoles(ctx, "user-1", []string{"editor"}); err != nil {
		t.Fatalf("SetIdentityRoles: %v", err)
	}

	for _, permission := range []string{"docs:write", "docs:read"} {
		allowed, err := strategy.HasPermission(ctx, "user-1", permission)
		if err != nil {
			t.Fatalf("HasPermission %q: %v", permission, err)
		}
		if !allowed {
			t.Errorf("editor was denied %q, which it inherits from viewer", permission)
		}
	}
}

// TestUndefinedRoleIsReported proves a missing definition fails loudly rather
// than resolving to no permissions — the two are indistinguishable to a caller
// otherwise.
func TestUndefinedRoleIsReported(t *testing.T) {
	ctx := context.Background()
	repo := newRBACRepo(t)
	strategy := rbac.NewStorageStrategy(repo, repo)

	if err := repo.SetIdentityRoles(ctx, "user-1", []string{"never-defined"}); err != nil {
		t.Fatalf("SetIdentityRoles: %v", err)
	}

	if _, err := strategy.HasPermission(ctx, "user-1", "anything"); !errors.Is(err, rbac.ErrRoleNotFound) {
		t.Fatalf("error = %v, want ErrRoleNotFound", err)
	}
}

// TestSetIdentityRolesReplaces proves revocation works: a role absent from the
// new set is removed rather than merged.
func TestSetIdentityRolesReplaces(t *testing.T) {
	ctx := context.Background()
	repo := newRBACRepo(t)

	if err := repo.SetIdentityRoles(ctx, "user-1", []string{"admin", "editor"}); err != nil {
		t.Fatalf("SetIdentityRoles: %v", err)
	}
	if err := repo.SetIdentityRoles(ctx, "user-1", []string{"editor"}); err != nil {
		t.Fatalf("SetIdentityRoles: %v", err)
	}

	roles, err := repo.GetIdentityRoles(ctx, "user-1")
	if err != nil {
		t.Fatalf("GetIdentityRoles: %v", err)
	}
	if len(roles) != 1 || roles[0] != "editor" {
		t.Errorf("roles = %v, want only editor; admin should have been revoked", roles)
	}
}

func TestRoleDefinitionRoundTrip(t *testing.T) {
	ctx := context.Background()
	repo := newRBACRepo(t)

	want := &rbac.Role{
		Name:        "auditor",
		Permissions: []string{"audit:read", "reports:**"},
		Inherits:    []string{"viewer"},
		Description: "Reads audit events and every report",
	}
	// The parent must exist for the definition to resolve.
	if err := repo.SaveRole(ctx, &rbac.Role{Name: "viewer", Permissions: []string{"docs:read"}}); err != nil {
		t.Fatalf("SaveRole: %v", err)
	}
	if err := repo.SaveRole(ctx, want); err != nil {
		t.Fatalf("SaveRole: %v", err)
	}

	got, err := repo.GetRole(ctx, "auditor")
	if err != nil {
		t.Fatalf("GetRole: %v", err)
	}
	if got.Name != want.Name || got.Description != want.Description {
		t.Errorf("role = %+v, want %+v", got, want)
	}
	if len(got.Permissions) != 2 || got.Permissions[1] != "reports:**" {
		t.Errorf("permissions did not round-trip: %v", got.Permissions)
	}
	if len(got.Inherits) != 1 || got.Inherits[0] != "viewer" {
		t.Errorf("inheritance did not round-trip: %v", got.Inherits)
	}

	roles, err := repo.ListRoles(ctx)
	if err != nil {
		t.Fatalf("ListRoles: %v", err)
	}
	if len(roles) != 2 {
		t.Errorf("ListRoles returned %d roles, want 2", len(roles))
	}

	if err := repo.DeleteRole(ctx, "auditor"); err != nil {
		t.Fatalf("DeleteRole: %v", err)
	}
	if _, err := repo.GetRole(ctx, "auditor"); !errors.Is(err, rbac.ErrRoleNotFound) {
		t.Errorf("error = %v, want ErrRoleNotFound after deletion", err)
	}
}
