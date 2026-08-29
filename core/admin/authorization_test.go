package admin

import (
	"bytes"
	"context"
	"errors"
	"os"
	"regexp"
	"sort"
	"testing"
	"unicode"
)

// The admin API is the privileged surface: every method here can read, mutate,
// or delete another tenant's users, roles, and audit trail. Before this file
// the package was 11.3% covered, and none of that touched authorization --
// only the password hasher and two HTTP helpers had tests.
//
// These tests are about the gate rather than the operations. A store that
// records whether it was reached is enough: if a refused call never touches
// storage, the gate held.

// spyStores records whether any storage operation ran. A refused call must
// leave every counter at zero.
type spyStores struct {
	reached int
}

func (s *spyStores) List(context.Context, ListOptions) (*UserListResult, error) {
	s.reached++
	return &UserListResult{}, nil
}
func (s *spyStores) Get(context.Context, any) (*User, error) {
	s.reached++
	return &User{ID: "u1"}, nil
}
func (s *spyStores) GetByEmail(context.Context, string) (*User, error) {
	s.reached++
	return nil, errors.New("not found")
}
func (s *spyStores) Create(context.Context, *User) error { s.reached++; return nil }
func (s *spyStores) Update(context.Context, *User) error { s.reached++; return nil }
func (s *spyStores) Delete(context.Context, any) error   { s.reached++; return nil }
func (s *spyStores) UpdateState(context.Context, any, UserState) error {
	s.reached++
	return nil
}

func (s *spyStores) ListByUser(context.Context, any) ([]Session, error) {
	s.reached++
	return nil, nil
}
func (s *spyStores) Revoke(context.Context, any) error       { s.reached++; return nil }
func (s *spyStores) RevokeByUser(context.Context, any) error { s.reached++; return nil }

func (s *spyStores) Query(context.Context, AuditQuery) (*AuditEventListResult, error) {
	s.reached++
	return &AuditEventListResult{}, nil
}

// spyRoles and spyTenants exist because their List, Get and Create collide
// with UserStore's: same names, different return types, so one type cannot
// implement all three. They share the reach counter so a leak through any
// store shows up the same way.
type spyRoles struct{ spy *spyStores }

func (s spyRoles) List(context.Context, ListOptions) (*RoleListResult, error) {
	s.spy.reached++
	return &RoleListResult{}, nil
}
func (s spyRoles) Get(context.Context, string) (*Role, error) {
	s.spy.reached++
	return &Role{ID: "r1"}, nil
}
func (s spyRoles) Create(context.Context, *Role) error  { s.spy.reached++; return nil }
func (s spyRoles) Update(context.Context, *Role) error  { s.spy.reached++; return nil }
func (s spyRoles) Delete(context.Context, string) error { s.spy.reached++; return nil }
func (s spyRoles) AssignToUser(context.Context, any, string) error {
	s.spy.reached++
	return nil
}
func (s spyRoles) RemoveFromUser(context.Context, any, string) error {
	s.spy.reached++
	return nil
}
func (s spyRoles) GetUserRoles(context.Context, any) ([]Role, error) {
	s.spy.reached++
	return nil, nil
}

type spyTenants struct{ spy *spyStores }

func (s spyTenants) List(context.Context, ListOptions) (*TenantListResult, error) {
	s.spy.reached++
	return &TenantListResult{}, nil
}
func (s spyTenants) Get(context.Context, string) (*Tenant, error) {
	s.spy.reached++
	return &Tenant{ID: "t1"}, nil
}
func (s spyTenants) Create(context.Context, *Tenant) error { s.spy.reached++; return nil }
func (s spyTenants) Update(context.Context, *Tenant) error { s.spy.reached++; return nil }
func (s spyTenants) Delete(context.Context, string) error  { s.spy.reached++; return nil }

func newSpyManager() (*Manager, *spyStores) {
	spy := &spyStores{}
	return NewManager(
		WithUserStore(spy),
		WithSessionStore(spy),
		WithAuditStore(spy),
		WithRoleStore(spyRoles{spy: spy}),
		WithTenantStore(spyTenants{spy: spy}),
	), spy
}

// call names one admin operation so a table can exercise the whole surface.
type call struct {
	name   string
	needs  string
	invoke func(*Manager, *Caller) error
}

func adminCalls() []call {
	ctx := context.Background()
	return []call{
		{"ListUsers", PermUsersRead, func(m *Manager, c *Caller) error {
			_, err := m.ListUsers(ctx, c, ListOptions{})
			return err
		}},
		{"GetUser", PermUsersRead, func(m *Manager, c *Caller) error {
			_, err := m.GetUser(ctx, c, "u1")
			return err
		}},
		{"UpdateUser", PermUsersWrite, func(m *Manager, c *Caller) error {
			_, err := m.UpdateUser(ctx, c, "u1", UpdateUserInput{})
			return err
		}},
		{"DeleteUser", PermUsersDelete, func(m *Manager, c *Caller) error {
			return m.DeleteUser(ctx, c, "u1")
		}},
		{"LockUser", PermUsersWrite, func(m *Manager, c *Caller) error {
			return m.LockUser(ctx, c, "u1", "abuse")
		}},
		{"UnlockUser", PermUsersWrite, func(m *Manager, c *Caller) error {
			return m.UnlockUser(ctx, c, "u1")
		}},
		{"ListUserSessions", PermSessionsRead, func(m *Manager, c *Caller) error {
			_, err := m.ListUserSessions(ctx, c, "u1")
			return err
		}},
		{"RevokeUserSessions", PermSessionsRevoke, func(m *Manager, c *Caller) error {
			return m.RevokeUserSessions(ctx, c, "u1")
		}},
		{"QueryAudit", PermAuditRead, func(m *Manager, c *Caller) error {
			_, err := m.QueryAudit(ctx, c, AuditQuery{})
			return err
		}},
		{"CreateUser", PermUsersWrite, func(m *Manager, c *Caller) error {
			_, err := m.CreateUser(ctx, c, CreateUserInput{Email: "new@example.test"})
			return err
		}},
		{"ListTenants", PermTenantsRead, func(m *Manager, c *Caller) error {
			_, err := m.ListTenants(ctx, c, ListOptions{})
			return err
		}},
		{"GetTenant", PermTenantsRead, func(m *Manager, c *Caller) error {
			_, err := m.GetTenant(ctx, c, "t1")
			return err
		}},
		{"CreateTenant", PermTenantsWrite, func(m *Manager, c *Caller) error {
			_, err := m.CreateTenant(ctx, c, CreateTenantInput{Name: "acme"})
			return err
		}},
		{"DeleteTenant", PermTenantsDelete, func(m *Manager, c *Caller) error {
			return m.DeleteTenant(ctx, c, "t1")
		}},
		{"ListRoles", PermRolesRead, func(m *Manager, c *Caller) error {
			_, err := m.ListRoles(ctx, c, ListOptions{})
			return err
		}},
		{"GetRole", PermRolesRead, func(m *Manager, c *Caller) error {
			_, err := m.GetRole(ctx, c, "r1")
			return err
		}},
		{"CreateRole", PermRolesWrite, func(m *Manager, c *Caller) error {
			_, err := m.CreateRole(ctx, c, CreateRoleInput{
				Name: "editor", Permissions: []string{PermUsersRead},
			})
			return err
		}},
		{"DeleteRole", PermRolesDelete, func(m *Manager, c *Caller) error {
			return m.DeleteRole(ctx, c, "r1")
		}},
		{"AssignRoleToUser", PermRolesWrite, func(m *Manager, c *Caller) error {
			return m.AssignRoleToUser(ctx, c, "u1", "r1")
		}},
		{"GetUserRoles", PermRolesRead, func(m *Manager, c *Caller) error {
			_, err := m.GetUserRoles(ctx, c, "u1")
			return err
		}},
	}
}

// TestEveryOperationRefusesANilCaller covers the unauthenticated path. A nil
// caller is the shape a handler produces when authentication did not run or
// its result was discarded, and it must never be treated as permitted.
func TestEveryOperationRefusesANilCaller(t *testing.T) {
	for _, c := range adminCalls() {
		t.Run(c.name, func(t *testing.T) {
			manager, spy := newSpyManager()
			err := c.invoke(manager, nil)
			if !errors.Is(err, ErrUnauthorized) {
				t.Errorf("error = %v, want ErrUnauthorized", err)
			}
			if spy.reached != 0 {
				t.Errorf("a nil caller reached storage %d time(s)", spy.reached)
			}
		})
	}
}

// TestEveryOperationRefusesAnUnprivilegedCaller covers the authenticated but
// unauthorized path: a real caller holding no permissions at all.
func TestEveryOperationRefusesAnUnprivilegedCaller(t *testing.T) {
	for _, c := range adminCalls() {
		t.Run(c.name, func(t *testing.T) {
			manager, spy := newSpyManager()
			err := c.invoke(manager, &Caller{ID: "nobody"})
			if !errors.Is(err, ErrForbidden) {
				t.Errorf("error = %v, want ErrForbidden", err)
			}
			if spy.reached != 0 {
				t.Errorf("an unprivileged caller reached storage %d time(s)", spy.reached)
			}
		})
	}
}

// TestEveryOperationAcceptsTheRightPermission is the other half. A gate that
// refuses everything is not an authorization system, and without this the
// tests above would pass against a manager that simply always denied.
func TestEveryOperationAcceptsTheRightPermission(t *testing.T) {
	for _, c := range adminCalls() {
		t.Run(c.name, func(t *testing.T) {
			manager, spy := newSpyManager()
			err := c.invoke(manager, &Caller{ID: "admin", Permissions: []string{c.needs}})
			if errors.Is(err, ErrForbidden) || errors.Is(err, ErrUnauthorized) {
				t.Fatalf("a caller holding %q was refused: %v", c.needs, err)
			}
			if spy.reached == 0 {
				t.Errorf("a permitted call never reached storage")
			}
		})
	}
}

// TestReadPermissionDoesNotGrantWrite pins the separation between the verbs.
// A viewer who can delete users is the failure this whole permission table
// exists to prevent.
func TestReadPermissionDoesNotGrantWrite(t *testing.T) {
	reader := &Caller{ID: "viewer", Permissions: []string{PermUsersRead}}

	manager, spy := newSpyManager()
	if err := manager.DeleteUser(context.Background(), reader, "u1"); !errors.Is(err, ErrForbidden) {
		t.Errorf("users:read allowed a delete: %v", err)
	}
	if spy.reached != 0 {
		t.Error("a refused delete reached storage")
	}

	if _, err := manager.UpdateUser(context.Background(), reader, "u1", UpdateUserInput{}); !errors.Is(err, ErrForbidden) {
		t.Errorf("users:read allowed an update: %v", err)
	}
}

// TestSuperAdminBypassesThePermissionTable documents the deliberate escape
// hatch, so a change to it is visible rather than incidental.
func TestSuperAdminBypassesThePermissionTable(t *testing.T) {
	manager, spy := newSpyManager()
	root := &Caller{ID: "root", IsSuperAdmin: true}

	if _, err := manager.ListUsers(context.Background(), root, ListOptions{}); err != nil {
		t.Fatalf("super admin was refused: %v", err)
	}
	if spy.reached == 0 {
		t.Error("super admin never reached storage")
	}
}

// TestRolesGrantTheirPermissions covers the indirect path: permissions
// resolved through DefaultRolePermissions rather than listed on the caller.
func TestRolesGrantTheirPermissions(t *testing.T) {
	manager, _ := newSpyManager()
	ctx := context.Background()

	viewer := &Caller{ID: "v", Roles: []string{"viewer"}}
	if _, err := manager.ListUsers(ctx, viewer, ListOptions{}); err != nil {
		t.Errorf("the viewer role was refused users:read: %v", err)
	}
	// A viewer must not inherit destructive permissions from the same table.
	if err := manager.DeleteUser(ctx, viewer, "u1"); !errors.Is(err, ErrForbidden) {
		t.Errorf("the viewer role was allowed users:delete: %v", err)
	}

	operator := &Caller{ID: "o", Roles: []string{"operator"}}
	if err := manager.RevokeUserSessions(ctx, operator, "u1"); err != nil {
		t.Errorf("the operator role was refused sessions:revoke: %v", err)
	}
	if err := manager.DeleteUser(ctx, operator, "u1"); !errors.Is(err, ErrForbidden) {
		t.Errorf("the operator role was allowed users:delete: %v", err)
	}
}

// TestUnknownRoleGrantsNothing keeps a typo in a role name from being
// interpreted as anything but a denial.
func TestUnknownRoleGrantsNothing(t *testing.T) {
	manager, spy := newSpyManager()
	caller := &Caller{ID: "x", Roles: []string{"adminn", "", "super-admin"}}

	if _, err := manager.ListUsers(context.Background(), caller, ListOptions{}); !errors.Is(err, ErrForbidden) {
		t.Errorf("an unknown role granted users:read: %v", err)
	}
	if spy.reached != 0 {
		t.Error("a caller with only unknown roles reached storage")
	}
}

// TestWildcardPermissions covers the two wildcard forms checkPerm accepts, and
// the boundary that keeps a prefix from spanning resources.
func TestWildcardPermissions(t *testing.T) {
	cases := []struct {
		name  string
		perms []string
		want  bool
	}{
		{"full wildcard", []string{"*"}, true},
		{"resource wildcard", []string{"users:*"}, true},
		{"exact permission", []string{PermUsersDelete}, true},
		{"different resource wildcard", []string{"tenants:*"}, false},
		{"read does not imply delete", []string{PermUsersRead}, false},
		{"no permissions", nil, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			manager, _ := newSpyManager()
			err := manager.DeleteUser(context.Background(), &Caller{ID: "c", Permissions: tc.perms}, "u1")
			allowed := !errors.Is(err, ErrForbidden) && !errors.Is(err, ErrUnauthorized)
			if allowed != tc.want {
				t.Errorf("permissions %v allowed users:delete = %v, want %v", tc.perms, allowed, tc.want)
			}
		})
	}
}

// TestAuditQueryIsScopedToTheCallersTenant covers a cross-tenant read.
//
// A tenant administrator querying the audit trail must see only their own
// tenant's events, whatever they put in the query. Trusting a caller-supplied
// TenantID here would let one customer read another's authentication history.
func TestAuditQueryIsScopedToTheCallersTenant(t *testing.T) {
	var seen AuditQuery
	manager := NewManager(WithAuditStore(auditFunc(func(_ context.Context, q AuditQuery) (*AuditEventListResult, error) {
		seen = q
		return &AuditEventListResult{}, nil
	})))

	caller := &Caller{ID: "a", TenantID: "tenant-a", Permissions: []string{PermAuditRead}}
	if _, err := manager.QueryAudit(context.Background(), caller, AuditQuery{TenantID: "tenant-b"}); err != nil {
		t.Fatalf("QueryAudit: %v", err)
	}
	if seen.TenantID != "tenant-a" {
		t.Errorf("the audit query ran against tenant %q; a caller-supplied tenant "+
			"overrode the caller's own", seen.TenantID)
	}
}

type auditFunc func(context.Context, AuditQuery) (*AuditEventListResult, error)

func (f auditFunc) Query(ctx context.Context, q AuditQuery) (*AuditEventListResult, error) {
	return f(ctx, q)
}

// TestEveryAuthorizingMethodIsInTheTable is why the tests above can call
// themselves "every operation".
//
// adminCalls is written by hand, and the tests that walk it are only as
// complete as somebody remembered to make it. It listed nine of twenty
// methods; the eleven it omitted were every role and every tenant operation,
// so nothing checked that CreateRole, DeleteRole, AssignRoleToUser or
// DeleteTenant refuse an unprivileged caller. They do -- but that was a
// property of the implementation rather than something a test held true.
//
// This finds the exported Manager methods that consult authorize and asserts
// the table names all of them, so a method added tomorrow fails here rather
// than going quietly untested.
func TestEveryAuthorizingMethodIsInTheTable(t *testing.T) {
	source, err := os.ReadFile("admin.go")
	if err != nil {
		t.Fatalf("read admin.go: %v", err)
	}

	// In scope: exported, hangs off *Manager, and consults authorize.
	// Anything else is not an authorization decision.
	signature := regexp.MustCompile(`func \(m \*Manager\) (\w+)\([^)]*\)[^{]*\{`)
	locations := signature.FindAllSubmatchIndex(source, -1)

	var authorizing []string
	for i, loc := range locations {
		name := string(source[loc[2]:loc[3]])
		if !unicode.IsUpper(rune(name[0])) {
			continue
		}
		end := len(source)
		if i+1 < len(locations) {
			end = locations[i+1][0]
		}
		if bytes.Contains(source[loc[1]:end], []byte("m.authorize(")) {
			authorizing = append(authorizing, name)
		}
	}
	if len(authorizing) == 0 {
		t.Fatal("found no authorizing methods; this test is not looking at what it thinks")
	}

	listed := map[string]bool{}
	for _, c := range adminCalls() {
		listed[c.name] = true
	}

	var missing []string
	for _, name := range authorizing {
		if !listed[name] {
			missing = append(missing, name)
		}
	}
	sort.Strings(missing)
	if len(missing) > 0 {
		t.Errorf("adminCalls omits %v; the tests that walk it claim to cover every "+
			"operation and would not exercise these at all", missing)
	}
}
