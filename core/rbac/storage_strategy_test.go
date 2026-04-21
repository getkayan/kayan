package rbac

import (
	"fmt"
	"testing"
)

type mockRBACStorage struct {
	data map[string][]string
}

func newMockRBACStorage() *mockRBACStorage {
	return &mockRBACStorage{data: make(map[string][]string)}
}

func (m *mockRBACStorage) GetIdentityRoles(identityID any) ([]string, error) {
	key := fmt.Sprintf("%v", identityID)
	return m.data[key], nil
}

func (m *mockRBACStorage) SetIdentityRoles(identityID any, roles []string) error {
	key := fmt.Sprintf("%v", identityID)
	m.data[key] = roles
	return nil
}

func TestStorageStrategy_HasRole(t *testing.T) {
	store := newMockRBACStorage()
	store.SetIdentityRoles("user1", []string{"admin", "editor"})

	s := NewStorageStrategy(store)
	s.DefineRole(&Role{Name: "admin", Permissions: []string{"read", "write"}})
	s.DefineRole(&Role{Name: "editor", Permissions: []string{"read"}})

	has, err := s.HasRole("user1", "admin")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !has {
		t.Fatal("expected HasRole to return true")
	}

	has, err = s.HasRole("user1", "viewer")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if has {
		t.Fatal("expected HasRole to return false for unassigned role")
	}
}

func TestStorageStrategy_GetRoles(t *testing.T) {
	store := newMockRBACStorage()
	store.SetIdentityRoles("user1", []string{"admin", "editor"})

	s := NewStorageStrategy(store)

	roles, err := s.GetRoles("user1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(roles) != 2 {
		t.Fatalf("expected 2 roles, got %d", len(roles))
	}
}

func TestStorageStrategy_HasPermission(t *testing.T) {
	store := newMockRBACStorage()
	store.SetIdentityRoles("user1", []string{"editor"})

	s := NewStorageStrategy(store)
	s.DefineRole(&Role{Name: "editor", Permissions: []string{"read", "comment"}})

	has, err := s.HasPermission("user1", "read")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !has {
		t.Fatal("expected HasPermission to return true")
	}

	has, err = s.HasPermission("user1", "delete")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if has {
		t.Fatal("expected HasPermission to return false")
	}
}

func TestStorageStrategy_GetPermissions(t *testing.T) {
	store := newMockRBACStorage()
	store.SetIdentityRoles("user1", []string{"admin", "editor"})

	s := NewStorageStrategy(store)
	s.DefineRole(&Role{Name: "admin", Permissions: []string{"read", "write", "delete"}})
	s.DefineRole(&Role{Name: "editor", Permissions: []string{"read", "comment"}})

	perms, err := s.GetPermissions("user1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// admin: read, write, delete + editor: read (dup), comment → 4 unique
	if len(perms) != 4 {
		t.Fatalf("expected 4 permissions, got %d: %v", len(perms), perms)
	}
}

func TestStorageStrategy_UnknownRole(t *testing.T) {
	store := newMockRBACStorage()
	// Role "ghost" is in store but NOT defined via DefineRole
	store.SetIdentityRoles("user1", []string{"ghost"})

	s := NewStorageStrategy(store)

	// GetRoles still returns it (it's in storage)
	roles, err := s.GetRoles("user1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(roles) != 1 || roles[0] != "ghost" {
		t.Fatalf("expected [ghost], got %v", roles)
	}

	// But no permissions resolve from it
	perms, err := s.GetPermissions("user1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(perms) != 0 {
		t.Fatalf("expected 0 permissions for unknown role, got %v", perms)
	}
}
