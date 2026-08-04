package rbac

import (
	"context"
	"testing"
)

func TestManager_Authorize(t *testing.T) {
	ctx := context.Background()
	s := NewMemoryStrategy()
	s.AddRole(&Role{Name: "admin"})
	s.AssignRole("user-1", "admin")
	mgr := NewManager(s)

	ok, err := mgr.Authorize(ctx, "user-1", "admin")
	if err != nil {
		t.Fatalf("Authorize error: %v", err)
	}
	if !ok {
		t.Error("expected Authorize to return true")
	}

	ok, err = mgr.Authorize(ctx, "user-1", "editor")
	if err != nil {
		t.Fatalf("Authorize error: %v", err)
	}
	if ok {
		t.Error("expected Authorize to return false for missing role")
	}
}

func TestManager_RequireRole(t *testing.T) {
	ctx := context.Background()
	s := NewMemoryStrategy()
	s.AddRole(&Role{Name: "admin"})
	s.AssignRole("user-1", "admin")
	mgr := NewManager(s)

	if err := mgr.RequireRole(ctx, "user-1", "admin"); err != nil {
		t.Errorf("expected no error, got %v", err)
	}
	if err := mgr.RequireRole(ctx, "user-1", "editor"); err == nil {
		t.Error("expected error for missing role")
	}
}

func TestManager_AuthorizePermission(t *testing.T) {
	ctx := context.Background()
	s := NewMemoryStrategy()
	s.AddRole(&Role{Name: "admin", Permissions: []string{"users:write", "users:read"}})
	s.AssignRole("user-1", "admin")
	mgr := NewManager(s)

	ok, err := mgr.AuthorizePermission(ctx, "user-1", "users:write")
	if err != nil {
		t.Fatalf("AuthorizePermission error: %v", err)
	}
	if !ok {
		t.Error("expected true")
	}

	ok, err = mgr.AuthorizePermission(ctx, "user-1", "users:delete")
	if err != nil {
		t.Fatalf("AuthorizePermission error: %v", err)
	}
	if ok {
		t.Error("expected false for missing permission")
	}
}

func TestManager_RequirePermission(t *testing.T) {
	ctx := context.Background()
	s := NewMemoryStrategy()
	s.AddRole(&Role{Name: "admin", Permissions: []string{"users:write"}})
	s.AssignRole("user-1", "admin")
	mgr := NewManager(s)

	if err := mgr.RequirePermission(ctx, "user-1", "users:write"); err != nil {
		t.Errorf("expected no error, got %v", err)
	}
	if err := mgr.RequirePermission(ctx, "user-1", "users:delete"); err == nil {
		t.Error("expected error for missing permission")
	}
}

func TestManager_GetRoles(t *testing.T) {
	ctx := context.Background()
	s := NewMemoryStrategy()
	s.AddRole(&Role{Name: "admin"})
	s.AddRole(&Role{Name: "editor"})
	s.AssignRole("user-1", "admin")
	s.AssignRole("user-1", "editor")
	mgr := NewManager(s)

	roles, err := mgr.GetRoles(ctx, "user-1")
	if err != nil {
		t.Fatalf("GetRoles error: %v", err)
	}
	if len(roles) != 2 {
		t.Errorf("expected 2 roles, got %d", len(roles))
	}
}

func TestManager_GetPermissions(t *testing.T) {
	ctx := context.Background()
	s := NewMemoryStrategy()
	s.AddRole(&Role{Name: "admin", Permissions: []string{"users:write", "users:read"}})
	s.AssignRole("user-1", "admin")
	mgr := NewManager(s)

	perms, err := mgr.GetPermissions(ctx, "user-1")
	if err != nil {
		t.Fatalf("GetPermissions error: %v", err)
	}
	if len(perms) != 2 {
		t.Errorf("expected 2 permissions, got %d", len(perms))
	}
}

func TestManager_NilStrategy(t *testing.T) {
	ctx := context.Background()
	mgr := NewManager(nil)

	_, err := mgr.Authorize(ctx, "user-1", "admin")
	if err == nil {
		t.Error("expected error for nil strategy")
	}

	_, err = mgr.AuthorizePermission(ctx, "user-1", "perm")
	if err == nil {
		t.Error("expected error for nil strategy")
	}
}
