package rbac

import "testing"

func TestMemoryStrategy_HasRole(t *testing.T) {
	s := NewMemoryStrategy()
	s.AddRole(&Role{Name: "admin", Permissions: []string{"users:write"}})
	s.AssignRole("user-1", "admin")

	has, err := s.HasRole("user-1", "admin")
	if err != nil {
		t.Fatalf("HasRole error: %v", err)
	}
	if !has {
		t.Error("expected HasRole to return true")
	}

	has, err = s.HasRole("user-1", "editor")
	if err != nil {
		t.Fatalf("HasRole error: %v", err)
	}
	if has {
		t.Error("expected HasRole to return false for unassigned role")
	}
}

func TestMemoryStrategy_AssignRole_UndefinedRole(t *testing.T) {
	s := NewMemoryStrategy()
	err := s.AssignRole("user-1", "nonexistent")
	if err == nil {
		t.Error("expected error for undefined role")
	}
}

func TestMemoryStrategy_UnassignRole(t *testing.T) {
	s := NewMemoryStrategy()
	s.AddRole(&Role{Name: "editor"})
	s.AssignRole("user-1", "editor")
	s.UnassignRole("user-1", "editor")

	has, _ := s.HasRole("user-1", "editor")
	if has {
		t.Error("expected HasRole to return false after UnassignRole")
	}
}

func TestMemoryStrategy_GetRoles(t *testing.T) {
	s := NewMemoryStrategy()
	s.AddRole(&Role{Name: "admin"})
	s.AddRole(&Role{Name: "editor"})
	s.AssignRole("user-1", "admin")
	s.AssignRole("user-1", "editor")

	roles, err := s.GetRoles("user-1")
	if err != nil {
		t.Fatalf("GetRoles error: %v", err)
	}
	if len(roles) != 2 {
		t.Fatalf("expected 2 roles, got %d", len(roles))
	}
}

func TestMemoryStrategy_HasPermission(t *testing.T) {
	s := NewMemoryStrategy()
	s.AddRole(&Role{Name: "admin", Permissions: []string{"users:write", "users:read"}})
	s.AssignRole("user-1", "admin")

	has, err := s.HasPermission("user-1", "users:write")
	if err != nil {
		t.Fatalf("HasPermission error: %v", err)
	}
	if !has {
		t.Error("expected HasPermission to return true")
	}

	has, err = s.HasPermission("user-1", "users:delete")
	if err != nil {
		t.Fatalf("HasPermission error: %v", err)
	}
	if has {
		t.Error("expected HasPermission to return false for missing permission")
	}
}

func TestMemoryStrategy_GetPermissions(t *testing.T) {
	s := NewMemoryStrategy()
	s.AddRole(&Role{Name: "admin", Permissions: []string{"users:write", "users:read"}})
	s.AddRole(&Role{Name: "editor", Permissions: []string{"posts:write", "users:read"}})
	s.AssignRole("user-1", "admin")
	s.AssignRole("user-1", "editor")

	perms, err := s.GetPermissions("user-1")
	if err != nil {
		t.Fatalf("GetPermissions error: %v", err)
	}
	// users:read appears in both, should be deduplicated
	if len(perms) != 3 {
		t.Fatalf("expected 3 unique permissions, got %d: %v", len(perms), perms)
	}
}

func TestMemoryStrategy_NoRoles(t *testing.T) {
	s := NewMemoryStrategy()

	roles, err := s.GetRoles("unknown")
	if err != nil {
		t.Fatalf("GetRoles error: %v", err)
	}
	if len(roles) != 0 {
		t.Errorf("expected 0 roles, got %d", len(roles))
	}

	perms, err := s.GetPermissions("unknown")
	if err != nil {
		t.Fatalf("GetPermissions error: %v", err)
	}
	if len(perms) != 0 {
		t.Errorf("expected 0 permissions, got %d", len(perms))
	}
}
