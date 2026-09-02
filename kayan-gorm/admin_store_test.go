package gormstore

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/getkayan/kayan/core/admin"
	"github.com/getkayan/kayan/core/audit"
	"github.com/getkayan/kayan/core/flow"
	"github.com/getkayan/kayan/core/identity"
	"github.com/getkayan/kayan/core/rbac"
	"github.com/getkayan/kayan/core/session"
	"github.com/getkayan/kayan/core/tenant"
)

func setupAdminStores(t *testing.T) (*Repository, *AdminStores) {
	t.Helper()
	repo := setupRepo(t)
	return repo, NewAdminStores(repo.DB())
}

func TestAdminStoresProvisionAWorkingAccount(t *testing.T) {
	ctx := context.Background()
	repo, stores := setupAdminStores(t)

	if err := stores.Roles.Create(ctx, &admin.Role{
		Name: "operator", Permissions: []string{admin.PermUsersRead, "documents:read"},
	}); err != nil {
		t.Fatalf("create role: %v", err)
	}
	manager := admin.NewManager(
		admin.WithUserStore(stores.Users),
		admin.WithSessionStore(stores.Sessions),
		admin.WithRoleStore(stores.Roles),
		admin.WithAuditStore(stores.Audit),
		admin.WithIDGenerator(func() any { return "user-1" }),
	)
	created, err := manager.CreateUser(ctx, &admin.Caller{IsSuperAdmin: true}, admin.CreateUserInput{
		Email: "operator@example.test", Password: "correct horse battery staple", Roles: []string{"operator"},
	})
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}

	_, login := flow.PasswordAuth(repo, func() any { return &identity.Identity{} }, "email")
	loggedIn, err := login.Authenticate(ctx, "password", "operator@example.test", "correct horse battery staple")
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	if loggedIn.(*identity.Identity).ID != created.ID {
		t.Fatalf("authenticated identity = %v, want %v", loggedIn.(*identity.Identity).ID, created.ID)
	}
	if _, err := login.Authenticate(ctx, "password", "operator@example.test", "wrong password"); err == nil {
		t.Fatal("wrong password authenticated")
	}

	caller, err := manager.ResolveCaller(ctx, created.ID)
	if err != nil {
		t.Fatalf("ResolveCaller: %v", err)
	}
	if _, err := manager.ListUsers(ctx, caller, admin.ListOptions{}); err != nil {
		t.Fatalf("role permission did not authorize ListUsers: %v", err)
	}

	rbacRepo := NewRBACRepository(repo.DB())
	allowed, err := rbac.NewStorageStrategy(rbacRepo, rbacRepo).HasPermission(ctx, created.ID, "documents:read")
	if err != nil || !allowed {
		t.Fatalf("persisted RBAC permission = %v, err = %v", allowed, err)
	}

	sessions := session.NewDatabaseStrategy(repo)
	issued, err := sessions.Create(ctx, "session-1", created.ID)
	if err != nil {
		t.Fatalf("create session: %v", err)
	}
	listed, err := manager.ListUserSessions(ctx, &admin.Caller{IsSuperAdmin: true}, created.ID)
	if err != nil || len(listed) != 1 {
		t.Fatalf("listed sessions = %v, err = %v", listed, err)
	}
	if err := manager.RevokeUserSessions(ctx, &admin.Caller{IsSuperAdmin: true}, created.ID); err != nil {
		t.Fatalf("revoke sessions: %v", err)
	}
	if _, err := sessions.Validate(ctx, issued.ID); err == nil {
		t.Fatal("revoked database session still validates")
	}

	event := &audit.AuditEvent{ID: "audit-1", Type: audit.EventLoginSuccess, ActorID: "user-1", Status: "success"}
	if err := repo.SaveEvent(ctx, event); err != nil {
		t.Fatalf("save audit event: %v", err)
	}
	audited, err := manager.QueryAudit(ctx, &admin.Caller{IsSuperAdmin: true}, admin.AuditQuery{UserID: "user-1"})
	if err != nil || audited.Total != 1 || len(audited.Data) != 1 {
		t.Fatalf("audit result = %#v, err = %v", audited, err)
	}
}

func TestAdminProvisionRollsBackEveryWriteForUnknownRole(t *testing.T) {
	ctx := context.Background()
	repo, stores := setupAdminStores(t)
	manager := admin.NewManager(
		admin.WithUserStore(stores.Users),
		admin.WithIDGenerator(func() any { return "partial-user" }),
	)

	_, err := manager.CreateUser(ctx, &admin.Caller{IsSuperAdmin: true}, admin.CreateUserInput{
		Email: "partial@example.test", Password: "correct horse battery staple", Roles: []string{"missing"},
	})
	if !errors.Is(err, rbac.ErrRoleNotFound) {
		t.Fatalf("error = %v, want rbac.ErrRoleNotFound", err)
	}
	for model, name := range map[any]string{
		&gormIdentity{}: "identity", &gormCredential{}: "credential", &RoleAssignment{}: "assignment",
	} {
		var count int64
		if err := repo.DB().Model(model).Count(&count).Error; err != nil {
			t.Fatalf("count %s: %v", name, err)
		}
		if count != 0 {
			t.Errorf("%s count = %d after failed provisioning, want 0", name, count)
		}
	}
}

func TestAdminEmailChangeMovesTheLoginIdentifier(t *testing.T) {
	ctx := context.Background()
	repo, stores := setupAdminStores(t)
	manager := admin.NewManager(
		admin.WithUserStore(stores.Users),
		admin.WithIDGenerator(func() any { return "user-1" }),
	)
	root := &admin.Caller{IsSuperAdmin: true}
	if _, err := manager.CreateUser(ctx, root, admin.CreateUserInput{
		Email: "old@example.test", Password: "correct horse battery staple",
	}); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}

	newEmail := "new@example.test"
	if _, err := manager.UpdateUser(ctx, root, "user-1", admin.UpdateUserInput{Email: &newEmail}); err != nil {
		t.Fatalf("UpdateUser: %v", err)
	}
	_, login := flow.PasswordAuth(repo, func() any { return &identity.Identity{} }, "email")
	if _, err := login.Authenticate(ctx, "password", newEmail, "correct horse battery staple"); err != nil {
		t.Fatalf("new email does not authenticate: %v", err)
	}
	if _, err := login.Authenticate(ctx, "password", "old@example.test", "correct horse battery staple"); err == nil {
		t.Fatal("old email still authenticates after the administrative change")
	}
}

func TestDeletingAdminUserRemovesEveryAuthenticationPath(t *testing.T) {
	ctx := context.Background()
	repo, stores := setupAdminStores(t)
	if err := stores.Roles.Create(ctx, &admin.Role{Name: "reader", Permissions: []string{"documents:read"}}); err != nil {
		t.Fatalf("create role: %v", err)
	}
	manager := admin.NewManager(
		admin.WithUserStore(stores.Users), admin.WithRoleStore(stores.Roles),
		admin.WithIDGenerator(func() any { return "user-1" }),
	)
	root := &admin.Caller{IsSuperAdmin: true}
	if _, err := manager.CreateUser(ctx, root, admin.CreateUserInput{
		Email: "delete@example.test", Password: "correct horse battery staple", Roles: []string{"reader"},
	}); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	sessions := session.NewDatabaseStrategy(repo)
	issued, err := sessions.Create(ctx, "session-1", "user-1")
	if err != nil {
		t.Fatalf("create session: %v", err)
	}
	if err := manager.DeleteUser(ctx, root, "user-1"); err != nil {
		t.Fatalf("DeleteUser: %v", err)
	}
	if _, err := sessions.Validate(ctx, issued.ID); err == nil {
		t.Fatal("deleted user's session still validates")
	}
	if _, err := repo.GetCredentialByIdentifier(ctx, "delete@example.test", "password"); err == nil {
		t.Fatal("deleted user's password credential remains")
	}
	roles, err := NewRBACRepository(repo.DB()).GetIdentityRoles(ctx, "user-1")
	if err != nil {
		t.Fatalf("get roles: %v", err)
	}
	if len(roles) != 0 {
		t.Fatalf("deleted user's role assignments remain: %v", roles)
	}
}

func TestLockingAdminUserRevokesExistingSessions(t *testing.T) {
	ctx := context.Background()
	repo, stores := setupAdminStores(t)
	manager := admin.NewManager(
		admin.WithUserStore(stores.Users),
		admin.WithIDGenerator(func() any { return "user-1" }),
	)
	root := &admin.Caller{IsSuperAdmin: true}
	if _, err := manager.CreateUser(ctx, root, admin.CreateUserInput{
		Email: "locked@example.test", Password: "correct horse battery staple",
	}); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	sessions := session.NewDatabaseStrategy(repo)
	issued, err := sessions.Create(ctx, "session-1", "user-1")
	if err != nil {
		t.Fatalf("create session: %v", err)
	}
	if err := manager.LockUser(ctx, root, "user-1", "incident response"); err != nil {
		t.Fatalf("LockUser: %v", err)
	}
	if _, err := sessions.Validate(ctx, issued.ID); err == nil {
		t.Fatal("session issued before the account lock still validates")
	}
}

func TestAdminAuditQueryPaginatesAndCountsIndependently(t *testing.T) {
	ctx := context.Background()
	repo, stores := setupAdminStores(t)
	for i := 0; i < 3; i++ {
		if err := repo.SaveEvent(ctx, &audit.AuditEvent{
			ID: string(rune('a' + i)), Type: "admin.test", ActorID: "operator",
			Status: "success", CreatedAt: time.Now().Add(time.Duration(i) * time.Second),
		}); err != nil {
			t.Fatalf("save event: %v", err)
		}
	}
	result, err := stores.Audit.Query(ctx, admin.AuditQuery{UserID: "operator", Limit: 1, Offset: 1})
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	if result.Total != 3 || len(result.Data) != 1 || result.Limit != 1 || result.Offset != 1 {
		t.Fatalf("result = %#v", result)
	}
}

func TestAdminCallerUsesTheRoleDefinitionFromItsOwnTenant(t *testing.T) {
	db := setupSQLiteDB(t)
	repo := NewRepository(db)
	if err := repo.AutoMigrateDev(); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	if err := RegisterTenantIsolation(db); err != nil {
		t.Fatalf("tenant isolation: %v", err)
	}
	stores := NewAdminStores(db)

	seed := []struct {
		tenantID, userID, permission string
	}{
		{"tenant-a", "user-a", "documents:read"},
		{"tenant-b", "user-b", "documents:delete"},
	}
	for _, item := range seed {
		ctx := tenant.WithTenantID(context.Background(), item.tenantID)
		if err := stores.Roles.Create(ctx, &admin.Role{
			Name: "operator", TenantID: item.tenantID, Permissions: []string{item.permission},
		}); err != nil {
			t.Fatalf("create %s role: %v", item.tenantID, err)
		}
		manager := admin.NewManager(
			admin.WithUserStore(stores.Users), admin.WithRoleStore(stores.Roles),
			admin.WithIDGenerator(func() any { return item.userID }),
		)
		if _, err := manager.CreateUser(ctx, &admin.Caller{IsSuperAdmin: true}, admin.CreateUserInput{
			Email: item.userID + "@example.test", Password: "correct horse battery staple",
			TenantID: item.tenantID, Roles: []string{"operator"},
		}); err != nil {
			t.Fatalf("create %s user: %v", item.tenantID, err)
		}
	}

	manager := admin.NewManager(admin.WithUserStore(stores.Users), admin.WithRoleStore(stores.Roles))
	caller, err := manager.ResolveCaller(tenant.WithTenantID(context.Background(), "tenant-a"), "user-a")
	if err != nil {
		t.Fatalf("ResolveCaller: %v", err)
	}
	if len(caller.Permissions) != 1 || caller.Permissions[0] != "documents:read" {
		t.Fatalf("tenant-a permissions = %v; tenant-b role leaked", caller.Permissions)
	}
	if _, err := manager.ResolveCaller(context.Background(), "user-a"); !errors.Is(err, tenant.ErrNoTenant) {
		t.Fatalf("unscoped ResolveCaller error = %v, want tenant.ErrNoTenant", err)
	}
}
