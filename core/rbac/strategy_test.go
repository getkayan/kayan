package rbac

import "testing"

type loaderIdentity struct {
	roles       []string
	permissions []string
}

func (i *loaderIdentity) GetRoles() []string {
	return i.roles
}

func (i *loaderIdentity) GetPermissions() []string {
	return i.permissions
}

func TestBasicStrategyUsesLoader(t *testing.T) {
	strategy := NewBasicStrategy(func(identityID any) (any, error) {
		if identityID != "user-1" {
			return nil, nil
		}
		return &loaderIdentity{
			roles:       []string{"admin"},
			permissions: []string{"users:write"},
		}, nil
	})

	hasRole, err := strategy.HasRole("user-1", "admin")
	if err != nil {
		t.Fatalf("HasRole returned error: %v", err)
	}
	if !hasRole {
		t.Fatal("expected loader-backed role lookup to succeed")
	}

	hasPermission, err := strategy.HasPermission("user-1", "users:write")
	if err != nil {
		t.Fatalf("HasPermission returned error: %v", err)
	}
	if !hasPermission {
		t.Fatal("expected loader-backed permission lookup to succeed")
	}
}
