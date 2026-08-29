package admin

import (
	"context"
	"errors"
	"testing"
)

// callerStores backs ResolveCaller with one user and one role assignment.
type callerStores struct {
	user *User
	err  error
}

func (c *callerStores) List(context.Context, ListOptions) (*UserListResult, error) {
	return &UserListResult{}, nil
}
func (c *callerStores) Get(_ context.Context, _ any) (*User, error) {
	if c.err != nil {
		return nil, c.err
	}
	return c.user, nil
}
func (c *callerStores) GetByEmail(context.Context, string) (*User, error) { return c.user, nil }
func (c *callerStores) Create(context.Context, *User) error               { return nil }
func (c *callerStores) Update(context.Context, *User) error               { return nil }
func (c *callerStores) Delete(context.Context, any) error                 { return nil }
func (c *callerStores) UpdateState(context.Context, any, UserState) error { return nil }

// roleReader serves the assignments ResolveCaller flattens.
type roleReader struct{ roles []Role }

func (r roleReader) List(context.Context, ListOptions) (*RoleListResult, error) {
	return &RoleListResult{}, nil
}
func (r roleReader) Get(context.Context, string) (*Role, error)        { return &Role{}, nil }
func (r roleReader) Create(context.Context, *Role) error               { return nil }
func (r roleReader) Update(context.Context, *Role) error               { return nil }
func (r roleReader) Delete(context.Context, string) error              { return nil }
func (r roleReader) AssignToUser(context.Context, any, string) error   { return nil }
func (r roleReader) RemoveFromUser(context.Context, any, string) error { return nil }
func (r roleReader) GetUserRoles(context.Context, any) ([]Role, error) { return r.roles, nil }

func callerManager(user *User, roles []Role) *Manager {
	return NewManager(
		WithUserStore(&callerStores{user: user}),
		WithRoleStore(roleReader{roles: roles}),
	)
}

// TestCustomRoleGrantsItsPermissions is the whole reason ResolveCaller exists.
//
// authorize resolves Caller.Roles against DefaultRolePermissions, a fixed
// table of built-in names. A role created with CreateRole is not in it, so a
// Caller carrying that role name authorizes nothing -- the role system appears
// broken rather than incomplete. Resolving flattens the role's own permissions
// onto the Caller, which is the step nothing performed.
func TestCustomRoleGrantsItsPermissions(t *testing.T) {
	manager := callerManager(
		&User{ID: "u1", State: UserStateActive, TenantID: "acme"},
		[]Role{{ID: "r1", Name: "content-editor", Permissions: []string{PermUsersRead}}},
	)

	caller, err := manager.ResolveCaller(context.Background(), "u1")
	if err != nil {
		t.Fatalf("ResolveCaller: %v", err)
	}

	if caller.ID != "u1" || caller.TenantID != "acme" {
		t.Errorf("caller = %+v, want the user's id and tenant", caller)
	}
	if err := manager.authorize(caller, PermUsersRead); err != nil {
		t.Errorf("a custom role did not grant its own permission: %v", err)
	}
	// And grants nothing it was not given.
	if err := manager.authorize(caller, PermUsersDelete); !errors.Is(err, ErrForbidden) {
		t.Errorf("error = %v, want the role to grant only what it lists", err)
	}
}

// TestBuiltInRoleStillWorks. Resolving keeps the role names, so a user holding
// a built-in role is still served by DefaultRolePermissions.
func TestBuiltInRoleStillWorks(t *testing.T) {
	manager := callerManager(
		&User{ID: "u1", State: UserStateActive},
		[]Role{{ID: "r1", Name: "admin"}},
	)

	caller, err := manager.ResolveCaller(context.Background(), "u1")
	if err != nil {
		t.Fatalf("ResolveCaller: %v", err)
	}
	if err := manager.authorize(caller, PermUsersDelete); err != nil {
		t.Errorf("the built-in admin role lost its permissions: %v", err)
	}
}

// TestResolvingADisabledUserIsRefused.
//
// An account that is not active must not resolve into a working Caller. Doing so
// would let a disabled administrator keep acting for as long as anything held
// the value -- and the whole point of locking an account is that it stops
// immediately.
func TestResolvingADisabledUserIsRefused(t *testing.T) {
	for _, state := range []UserState{UserStateLocked, UserStateInactive, UserStatePending} {
		t.Run(string(state), func(t *testing.T) {
			manager := callerManager(
				&User{ID: "u1", State: state},
				[]Role{{Name: "admin"}},
			)

			caller, err := manager.ResolveCaller(context.Background(), "u1")
			if err == nil {
				t.Fatalf("a %s user resolved to a caller", state)
			}
			if caller != nil {
				t.Error("a caller was returned alongside the error")
			}
			if !errors.Is(err, ErrForbidden) {
				t.Errorf("error = %v, want ErrForbidden", err)
			}
		})
	}
}

// TestResolveNeverGrantsSuperAdmin.
//
// IsSuperAdmin bypasses the permission table entirely. Deriving it from a role
// name would let anyone holding roles:write name a role "superadmin", assign
// it to themselves, and skip every check -- privilege escalation through the
// role editor. Granting it stays an explicit act by the application.
func TestResolveNeverGrantsSuperAdmin(t *testing.T) {
	for _, name := range []string{"superadmin", "super_admin", "root", "admin"} {
		manager := callerManager(
			&User{ID: "u1", State: UserStateActive},
			[]Role{{Name: name, Permissions: []string{PermUsersRead}}},
		)

		caller, err := manager.ResolveCaller(context.Background(), "u1")
		if err != nil {
			t.Fatalf("ResolveCaller: %v", err)
		}
		if caller.IsSuperAdmin {
			t.Errorf("a role named %q resolved to a super admin", name)
		}
	}
}

// TestResolveDeduplicatesPermissions. Two roles commonly overlap; a Caller
// carrying the same permission twice is harmless but makes an audit log of the
// caller misleading about what was actually granted.
func TestResolveDeduplicatesPermissions(t *testing.T) {
	manager := callerManager(
		&User{ID: "u1", State: UserStateActive},
		[]Role{
			{Name: "reader", Permissions: []string{PermUsersRead, PermRolesRead}},
			{Name: "auditor", Permissions: []string{PermUsersRead}},
		},
	)

	caller, err := manager.ResolveCaller(context.Background(), "u1")
	if err != nil {
		t.Fatalf("ResolveCaller: %v", err)
	}
	seen := map[string]int{}
	for _, p := range caller.Permissions {
		seen[p]++
	}
	if seen[PermUsersRead] != 1 {
		t.Errorf("%s appears %d times", PermUsersRead, seen[PermUsersRead])
	}
	if len(caller.Roles) != 2 {
		t.Errorf("roles = %v, want both names kept", caller.Roles)
	}
}

// TestResolveWithoutStoresIsRefused. A manager missing either store cannot
// answer the question, and must not answer it with an empty Caller that
// authorizes nothing while looking like a real one.
func TestResolveWithoutStoresIsRefused(t *testing.T) {
	if _, err := NewManager().ResolveCaller(context.Background(), "u1"); !errors.Is(err, ErrNotConfigured) {
		t.Errorf("error = %v, want ErrNotConfigured", err)
	}
}
