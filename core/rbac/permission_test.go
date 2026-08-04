package rbac

import (
	"context"
	"errors"
	"testing"
)

func TestPermissionGranted(t *testing.T) {
	tests := []struct {
		granted   string
		requested string
		want      bool
	}{
		// Exact matches.
		{"users:read", "users:read", true},
		{"users:read", "users:write", false},
		{"users:read", "posts:read", false},

		// Single-segment wildcard.
		{"users:*", "users:read", true},
		{"users:*", "users:delete", true},
		{"users:*", "posts:read", false},
		// One segment means one: it does not span a deeper path.
		{"users:*", "users:profile:read", false},
		{"*:read", "users:read", true},
		{"*:read", "users:write", false},
		{"*", "users", true},
		{"*", "users:read", false},

		// Multi-segment wildcard.
		{"users:**", "users:read", true},
		{"users:**", "users:profile:read", true},
		{"users:**", "users:a:b:c:d", true},
		{"users:**", "posts:read", false},
		// It matches at least one segment, so it does not grant the bare
		// prefix on its own.
		{"users:**", "users", false},
		{"**", "anything:at:all", true},

		// A grant more specific than the request does not satisfy it.
		{"users:read:own", "users:read", false},

		// A wildcard in the request would let a caller probe for any
		// permission at all, so it never matches.
		{"users:read", "users:*", false},
		{"users:*", "users:*", true}, // identical strings still match
		{"users:read", "*", false},
		{"*", "*", true},

		// Empty operands grant nothing.
		{"", "users:read", false},
		{"users:read", "", false},
		{"", "", false},

		// Matching is case-sensitive: "Admin" and "admin" being the same
		// permission is a surprise nobody asked for.
		{"users:Read", "users:read", false},
	}

	for _, tc := range tests {
		t.Run(tc.granted+" vs "+tc.requested, func(t *testing.T) {
			if got := PermissionGranted(tc.granted, tc.requested); got != tc.want {
				t.Errorf("PermissionGranted(%q, %q) = %v, want %v",
					tc.granted, tc.requested, got, tc.want)
			}
		})
	}
}

// TestWildcardCannotBeUsedToProbe is the property that keeps a wildcard from
// working in reverse: asking "may I do anything?" must not be answered yes
// because some narrow grant exists.
func TestWildcardCannotBeUsedToProbe(t *testing.T) {
	granted := []string{"users:read", "posts:write"}

	for _, probe := range []string{"*", "**", "users:*", "*:read", "*:*"} {
		t.Run(probe, func(t *testing.T) {
			if AnyPermissionGranted(granted, probe) {
				t.Errorf("a wildcard request %q was granted by %v", probe, granted)
			}
		})
	}
}

// TestRoleInheritance proves a role receives the permissions of the roles it
// inherits, so the two definitions cannot drift apart.
func TestRoleInheritance(t *testing.T) {
	ctx := context.Background()
	strategy := NewMemoryStrategy()

	for _, role := range []*Role{
		{Name: "viewer", Permissions: []string{"docs:read"}},
		{Name: "editor", Permissions: []string{"docs:write"}, Inherits: []string{"viewer"}},
		{Name: "admin", Permissions: []string{"docs:delete"}, Inherits: []string{"editor"}},
	} {
		if err := strategy.DefineRole(role); err != nil {
			t.Fatalf("DefineRole %s: %v", role.Name, err)
		}
	}

	if err := strategy.AssignRole("user-1", "admin"); err != nil {
		t.Fatalf("AssignRole: %v", err)
	}

	// An admin holds its own permission and everything up the chain.
	for _, permission := range []string{"docs:delete", "docs:write", "docs:read"} {
		allowed, err := strategy.HasPermission(ctx, "user-1", permission)
		if err != nil {
			t.Fatalf("HasPermission: %v", err)
		}
		if !allowed {
			t.Errorf("admin was denied %q, which it inherits", permission)
		}
	}

	// Inheritance flows one way only.
	if err := strategy.AssignRole("user-2", "viewer"); err != nil {
		t.Fatalf("AssignRole: %v", err)
	}
	allowed, err := strategy.HasPermission(ctx, "user-2", "docs:delete")
	if err != nil {
		t.Fatalf("HasPermission: %v", err)
	}
	if allowed {
		t.Error("a viewer was granted an admin permission; inheritance must not flow downward")
	}
}

// TestInheritanceCycleIsRejected proves a cycle is caught when the role is
// defined, rather than exhausting the stack during a permission check.
func TestInheritanceCycleIsRejected(t *testing.T) {
	strategy := NewMemoryStrategy()

	if err := strategy.DefineRole(&Role{Name: "a", Inherits: []string{"b"}}); err == nil {
		t.Fatal("a role inheriting an undefined role was accepted")
	}

	// Build a legitimate chain, then close it into a cycle.
	if err := strategy.DefineRole(&Role{Name: "b", Permissions: []string{"x"}}); err != nil {
		t.Fatalf("DefineRole b: %v", err)
	}
	if err := strategy.DefineRole(&Role{Name: "a", Inherits: []string{"b"}}); err != nil {
		t.Fatalf("DefineRole a: %v", err)
	}

	err := strategy.DefineRole(&Role{Name: "b", Permissions: []string{"x"}, Inherits: []string{"a"}})
	if !errors.Is(err, ErrCycle) {
		t.Fatalf("error = %v, want ErrCycle", err)
	}

	// The rejected edit must leave the previous definition intact: dropping it
	// would deny every identity holding the role.
	role, err := strategy.GetRole(context.Background(), "b")
	if err != nil {
		t.Fatalf("the previous definition was removed by a rejected edit: %v", err)
	}
	if len(role.Inherits) != 0 {
		t.Errorf("the cyclic definition was stored: %+v", role)
	}
	if len(role.Permissions) != 1 || role.Permissions[0] != "x" {
		t.Errorf("the previous permissions were lost: %+v", role)
	}
}

// TestUndefinedRoleIsReported proves an assignment naming a role with no
// definition fails loudly.
//
// Silently treating it as "no permissions" is indistinguishable from a
// legitimate denial, and it is exactly what the multi-replica bug looked like.
func TestUndefinedRoleIsReported(t *testing.T) {
	ctx := context.Background()
	strategy := NewMemoryStrategy()

	// Assign a role, then remove its definition. This is what a replica saw
	// when definitions were process-local: an assignment naming a role it had
	// never been told about.
	if err := strategy.DefineRole(&Role{Name: "ghost", Permissions: []string{"x"}}); err != nil {
		t.Fatalf("DefineRole: %v", err)
	}
	if err := strategy.AssignRole("user-1", "ghost"); err != nil {
		t.Fatalf("AssignRole: %v", err)
	}
	if err := strategy.DeleteRole(ctx, "ghost"); err != nil {
		t.Fatalf("DeleteRole: %v", err)
	}

	_, err := strategy.HasPermission(ctx, "user-1", "anything")
	if !errors.Is(err, ErrRoleNotFound) {
		t.Fatalf("error = %v, want ErrRoleNotFound", err)
	}
}

// TestAssignRoleRejectsUndefinedRole proves a typo in an assignment surfaces
// where it was made.
func TestAssignRoleRejectsUndefinedRole(t *testing.T) {
	strategy := NewMemoryStrategy()

	if err := strategy.AssignRole("user-1", "nonexistent"); !errors.Is(err, ErrRoleNotFound) {
		t.Fatalf("error = %v, want ErrRoleNotFound", err)
	}
}

func TestPermissionsAreDeduplicated(t *testing.T) {
	ctx := context.Background()
	strategy := NewMemoryStrategy()

	// Two roles granting the same permission by different routes.
	if err := strategy.DefineRole(&Role{Name: "base", Permissions: []string{"docs:read"}}); err != nil {
		t.Fatalf("DefineRole: %v", err)
	}
	if err := strategy.DefineRole(&Role{
		Name: "extra", Permissions: []string{"docs:read"}, Inherits: []string{"base"},
	}); err != nil {
		t.Fatalf("DefineRole: %v", err)
	}

	if err := strategy.AssignRole("user-1", "base"); err != nil {
		t.Fatalf("AssignRole: %v", err)
	}
	if err := strategy.AssignRole("user-1", "extra"); err != nil {
		t.Fatalf("AssignRole: %v", err)
	}

	permissions, err := strategy.GetPermissions(ctx, "user-1")
	if err != nil {
		t.Fatalf("GetPermissions: %v", err)
	}

	seen := make(map[string]int)
	for _, p := range permissions {
		seen[p]++
	}
	if seen["docs:read"] != 1 {
		t.Errorf("docs:read appears %d times, want 1", seen["docs:read"])
	}
}
