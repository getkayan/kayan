package rbac

import (
	"context"
	"errors"
	"testing"
)

// newTestStorageStrategy returns a strategy over one shared store, which is
// how a real deployment is wired: assignments and definitions in the same
// database.
func newTestStorageStrategy() (*StorageStrategy, *sharedStore) {
	store := newSharedStore()
	return NewStorageStrategy(store, store), store
}

func TestStorageStrategyHasRole(t *testing.T) {
	ctx := context.Background()
	strategy, store := newTestStorageStrategy()

	if err := strategy.DefineRole(ctx, &Role{Name: "admin", Permissions: []string{"users:delete"}}); err != nil {
		t.Fatalf("DefineRole: %v", err)
	}
	if err := store.SetIdentityRoles(ctx, "user-1", []string{"admin"}); err != nil {
		t.Fatalf("SetIdentityRoles: %v", err)
	}

	held, err := strategy.HasRole(ctx, "user-1", "admin")
	if err != nil {
		t.Fatalf("HasRole: %v", err)
	}
	if !held {
		t.Error("the assigned role was not reported")
	}

	held, err = strategy.HasRole(ctx, "user-1", "editor")
	if err != nil {
		t.Fatalf("HasRole: %v", err)
	}
	if held {
		t.Error("an unassigned role was reported as held")
	}
}

func TestStorageStrategyGetRoles(t *testing.T) {
	ctx := context.Background()
	strategy, store := newTestStorageStrategy()

	if err := store.SetIdentityRoles(ctx, "user-1", []string{"admin", "editor"}); err != nil {
		t.Fatalf("SetIdentityRoles: %v", err)
	}

	roles, err := strategy.GetRoles(ctx, "user-1")
	if err != nil {
		t.Fatalf("GetRoles: %v", err)
	}
	if len(roles) != 2 {
		t.Errorf("got %d roles, want 2", len(roles))
	}
}

func TestStorageStrategyHasPermission(t *testing.T) {
	ctx := context.Background()
	strategy, store := newTestStorageStrategy()

	if err := strategy.DefineRole(ctx, &Role{
		Name: "editor", Permissions: []string{"docs:read", "docs:write"},
	}); err != nil {
		t.Fatalf("DefineRole: %v", err)
	}
	if err := store.SetIdentityRoles(ctx, "user-1", []string{"editor"}); err != nil {
		t.Fatalf("SetIdentityRoles: %v", err)
	}

	for _, tc := range []struct {
		permission string
		want       bool
	}{
		{"docs:read", true},
		{"docs:write", true},
		{"docs:delete", false},
		{"billing:read", false},
	} {
		t.Run(tc.permission, func(t *testing.T) {
			allowed, err := strategy.HasPermission(ctx, "user-1", tc.permission)
			if err != nil {
				t.Fatalf("HasPermission: %v", err)
			}
			if allowed != tc.want {
				t.Errorf("HasPermission(%q) = %v, want %v", tc.permission, allowed, tc.want)
			}
		})
	}
}

func TestStorageStrategyGetPermissions(t *testing.T) {
	ctx := context.Background()
	strategy, store := newTestStorageStrategy()

	if err := strategy.DefineRole(ctx, &Role{Name: "a", Permissions: []string{"one", "two"}}); err != nil {
		t.Fatalf("DefineRole: %v", err)
	}
	if err := strategy.DefineRole(ctx, &Role{Name: "b", Permissions: []string{"two", "three"}}); err != nil {
		t.Fatalf("DefineRole: %v", err)
	}
	if err := store.SetIdentityRoles(ctx, "user-1", []string{"a", "b"}); err != nil {
		t.Fatalf("SetIdentityRoles: %v", err)
	}

	permissions, err := strategy.GetPermissions(ctx, "user-1")
	if err != nil {
		t.Fatalf("GetPermissions: %v", err)
	}
	// Three distinct permissions across two roles, with the overlap collapsed.
	if len(permissions) != 3 {
		t.Errorf("got %v, want three distinct permissions", permissions)
	}
}

// TestStorageStrategyUnknownRoleIsReported replaces a test that asserted the
// opposite.
//
// The previous version expected an assignment naming an undefined role to
// resolve to no permissions, and treated that as correct. It is precisely the
// multi-replica bug: a role defined on another replica was unknown here, and
// the resulting denial was indistinguishable from a legitimate one. Reporting
// it is what makes the difference visible.
func TestStorageStrategyUnknownRoleIsReported(t *testing.T) {
	ctx := context.Background()
	strategy, store := newTestStorageStrategy()

	if err := store.SetIdentityRoles(ctx, "user-1", []string{"ghost"}); err != nil {
		t.Fatalf("SetIdentityRoles: %v", err)
	}

	// The assignment itself is still readable: it exists in storage.
	roles, err := strategy.GetRoles(ctx, "user-1")
	if err != nil {
		t.Fatalf("GetRoles: %v", err)
	}
	if len(roles) != 1 || roles[0] != "ghost" {
		t.Fatalf("GetRoles = %v, want [ghost]", roles)
	}

	// Resolving its permissions must fail rather than silently yield none.
	if _, err := strategy.GetPermissions(ctx, "user-1"); !errors.Is(err, ErrRoleNotFound) {
		t.Fatalf("error = %v, want ErrRoleNotFound", err)
	}
	if _, err := strategy.HasPermission(ctx, "user-1", "anything"); !errors.Is(err, ErrRoleNotFound) {
		t.Fatalf("error = %v, want ErrRoleNotFound", err)
	}
}
