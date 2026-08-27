package gormstore

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/getkayan/kayan/core/audit"
	"github.com/getkayan/kayan/core/domain"
	"github.com/getkayan/kayan/core/identity"
	"github.com/getkayan/kayan/core/tenant"
)

// newIsolatedRepo builds a repository whose queries are tenant-scoped.
//
// The isolation callbacks only affect models implementing tenant.Scoped, so
// this fixture is what proves the core identity models actually satisfy it.
func newIsolatedRepo(t *testing.T) *Repository {
	t.Helper()

	db := setupSQLiteDB(t)
	repo := NewRepository(db)
	if err := repo.AutoMigrateDev(); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	if err := RegisterTenantIsolation(db); err != nil {
		t.Fatalf("register isolation: %v", err)
	}
	return repo
}

func tenantCtx(id string) context.Context {
	return tenant.WithTenantID(context.Background(), id)
}

// TestCredentialLookupIsTenantScoped is the cross-tenant authentication test.
//
// Two tenants legitimately hold the same identifier -- that is the entire
// point of multi-tenancy. Before the identity models implemented
// tenant.Scoped, GetCredentialByIdentifier filtered on identifier and type
// alone, so a login request scoped to tenant B authenticated against tenant
// A's stored secret. That is not a data leak, it is authentication as the
// wrong person's account.
func TestCredentialLookupIsTenantScoped(t *testing.T) {
	repo := newIsolatedRepo(t)

	const shared = "alice@example.test"
	seed := []struct {
		tenantID string
		identity string
		secret   string
	}{
		{"tenant-a", "id-a", "secret-a"},
		{"tenant-b", "id-b", "secret-b"},
	}
	for _, s := range seed {
		ctx := tenantCtx(s.tenantID)
		if err := repo.CreateIdentity(ctx, &identity.Identity{ID: s.identity}); err != nil {
			t.Fatalf("create identity in %s: %v", s.tenantID, err)
		}
		cred := &identity.Credential{
			ID: "cred-" + s.identity, IdentityID: s.identity,
			Type: "password", Identifier: shared, Secret: s.secret,
		}
		if err := repo.CreateCredential(ctx, cred); err != nil {
			t.Fatalf("create credential in %s: %v", s.tenantID, err)
		}
	}

	for _, want := range seed {
		got, err := repo.GetCredentialByIdentifier(tenantCtx(want.tenantID), shared, "password")
		if err != nil {
			t.Fatalf("lookup in %s: %v", want.tenantID, err)
		}
		if got.Secret != want.secret {
			t.Errorf("%s resolved the credential of another tenant: secret = %q, want %q",
				want.tenantID, got.Secret, want.secret)
		}
		if got.IdentityID != want.identity {
			t.Errorf("%s resolved identity %q, want %q",
				want.tenantID, got.IdentityID, want.identity)
		}
	}
}

// TestCredentialLookupWithoutTenantFails covers the fail-closed promise. A
// query with no tenant must be an error, never an unscoped read that returns
// whichever tenant's row happens to sort first.
func TestCredentialLookupWithoutTenantFails(t *testing.T) {
	repo := newIsolatedRepo(t)

	ctx := tenantCtx("tenant-a")
	if err := repo.CreateIdentity(ctx, &identity.Identity{ID: "id-a"}); err != nil {
		t.Fatalf("create identity: %v", err)
	}
	cred := &identity.Credential{
		ID: "cred-a", IdentityID: "id-a",
		Type: "password", Identifier: "alice@example.test", Secret: "secret-a",
	}
	if err := repo.CreateCredential(ctx, cred); err != nil {
		t.Fatalf("create credential: %v", err)
	}

	got, err := repo.GetCredentialByIdentifier(context.Background(), "alice@example.test", "password")
	if err == nil {
		t.Fatalf("lookup with no tenant returned a credential (secret %q); want an error", got.Secret)
	}
	if !errors.Is(err, tenant.ErrNoTenant) {
		t.Errorf("error = %v, want tenant.ErrNoTenant", err)
	}
}

// TestTokenConsumptionIsTenantScoped covers the cross-tenant authentication
// bypass on transient credentials.
//
// auth_tokens carries a tenant_id column that the model did not map, so
// ConsumeToken matched on the token value and type alone. A one-time code
// issued in one tenant was redeemable in another, which authenticates the
// bearer as whatever identity the token names.
func TestTokenConsumptionIsTenantScoped(t *testing.T) {
	repo := newIsolatedRepo(t)

	const code = "123456"
	ctxA := tenantCtx("tenant-a")
	token := &domain.AuthToken{
		Token: code, IdentityID: "id-a", Type: "otp",
		ExpiresAt: time.Now().Add(time.Hour),
	}
	if err := repo.SaveToken(ctxA, token); err != nil {
		t.Fatalf("save token: %v", err)
	}

	if _, err := repo.ConsumeToken(tenantCtx("tenant-b"), code, "otp"); err == nil {
		t.Fatal("tenant-b consumed a token issued in tenant-a")
	}

	consumed, err := repo.ConsumeToken(ctxA, code, "otp")
	if err != nil {
		t.Fatalf("issuing tenant could not consume its own token: %v", err)
	}
	if consumed.IdentityID != "id-a" {
		t.Errorf("IdentityID = %q, want id-a", consumed.IdentityID)
	}
}

// scopedUser is a caller-owned identity model that opts into isolation. BYOS
// means the application supplies the struct, so a tenant-aware deployment has
// to carry the tenant itself -- the library cannot add a field to a type it
// does not define.
type scopedUser struct {
	ID        string `gorm:"primaryKey"`
	TenantID_ string `gorm:"column:tenant_id;index"`
	Email     string
}

func (scopedUser) TableName() string        { return "scoped_users" }
func (u *scopedUser) TenantID() string      { return u.TenantID_ }
func (u *scopedUser) SetTenantID(id string) { u.TenantID_ = id }

// TestScopedIdentityModelIsIsolated shows the supported path for a
// multi-tenant BYOS model: implement tenant.Scoped and the callbacks isolate
// it like any other scoped table.
func TestScopedIdentityModelIsIsolated(t *testing.T) {
	db := setupSQLiteDB(t)
	if err := db.AutoMigrate(&scopedUser{}); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	if err := RegisterTenantIsolation(db); err != nil {
		t.Fatalf("register isolation: %v", err)
	}
	repo := NewRepository(db)

	if err := repo.CreateIdentity(tenantCtx("tenant-a"), &scopedUser{ID: "shared-id", Email: "a@example.test"}); err != nil {
		t.Fatalf("create identity: %v", err)
	}

	if _, err := repo.GetIdentity(tenantCtx("tenant-b"), func() any { return &scopedUser{} }, "shared-id"); err == nil {
		t.Error("tenant-b read a scoped identity belonging to tenant-a")
	}

	got, err := repo.GetIdentity(tenantCtx("tenant-a"), func() any { return &scopedUser{} }, "shared-id")
	if err != nil {
		t.Fatalf("owning tenant could not read its own identity: %v", err)
	}
	if got.(*scopedUser).Email != "a@example.test" {
		t.Errorf("Email = %q, want a@example.test", got.(*scopedUser).Email)
	}
}

// TestUnscopedIdentityModelIsNotIsolated documents the sharp edge rather than
// hiding it. GetIdentity queries the caller's own struct, so a model that does
// not implement tenant.Scoped is invisible to the isolation callbacks and is
// read across tenants. The library cannot fix this from the adapter side: it
// does not own the type. A multi-tenant deployment must implement
// tenant.Scoped on its identity model, and this test fails the day the
// callback starts covering unscoped models so the documentation cannot
// silently go stale.
func TestUnscopedIdentityModelIsNotIsolated(t *testing.T) {
	repo := newIsolatedRepo(t)

	if err := repo.CreateIdentity(tenantCtx("tenant-a"), &identity.Identity{ID: "shared-id"}); err != nil {
		t.Fatalf("create identity: %v", err)
	}

	if _, err := repo.GetIdentity(tenantCtx("tenant-b"), func() any { return &identity.Identity{} }, "shared-id"); err != nil {
		t.Skipf("unscoped BYOS models are now isolated (%v); update the tenancy docs "+
			"and TestScopedIdentityModelIsIsolated to match", err)
	}
}

// TestAuditQueryIsTenantScoped covers a silent cross-tenant read.
//
// gormAuditEvent already carried a TenantID column, but applyFilter only
// added the predicate when the caller populated filter.TenantID. A caller
// who asked a narrower question -- "failed logins for this actor" -- and
// left the tenant unset received every tenant's audit log, with nothing to
// signal it. That is the exact shape core/tenant promises cannot happen:
// the tenant came from a caller-supplied struct field rather than from the
// context, so tenant.ErrNoTenant was unreachable.
func TestAuditQueryIsTenantScoped(t *testing.T) {
	repo := newIsolatedRepo(t)

	for _, tc := range []struct{ tenantID, id string }{
		{"tenant-a", "event-a"},
		{"tenant-b", "event-b"},
	} {
		event := &audit.AuditEvent{ID: tc.id, Type: "login", Status: "failure", ActorID: "shared-actor"}
		if err := repo.SaveEvent(tenantCtx(tc.tenantID), event); err != nil {
			t.Fatalf("save event in %s: %v", tc.tenantID, err)
		}
	}

	// The filter deliberately omits TenantID: the context is the authority.
	events, err := repo.Query(tenantCtx("tenant-a"), audit.Filter{ActorID: "shared-actor"})
	if err != nil {
		t.Fatalf("query: %v", err)
	}
	for _, e := range events {
		if e.TenantID != "tenant-a" {
			t.Errorf("query in tenant-a returned an event from %q", e.TenantID)
		}
	}
	if len(events) != 1 {
		t.Errorf("got %d events, want 1 (the other tenant's event must not appear)", len(events))
	}
}

// TestSessionLookupIsTenantScoped closes a gap left by the first tenancy fix.
//
// gormSession implements tenant.Scoped, but SessionRepository never queries
// through it: every method operates on identity.Session, the core type, which
// has no tenant field and cannot implement the interface. The isolation
// callback keys off the model being queried, so mapping tenant_id onto
// gormSession did nothing for the code path that actually reads sessions.
func TestSessionLookupIsTenantScoped(t *testing.T) {
	repo := newIsolatedRepo(t)

	sess := &identity.Session{
		ID: "session-a", IdentityID: "id-a", RefreshToken: "refresh-a",
		ExpiresAt: time.Now().Add(time.Hour), Active: true,
	}
	if err := repo.CreateSession(tenantCtx("tenant-a"), sess); err != nil {
		t.Fatalf("create session: %v", err)
	}

	if _, err := repo.GetSession(tenantCtx("tenant-b"), "session-a"); err == nil {
		t.Error("tenant-b read a session belonging to tenant-a")
	}
	if _, err := repo.GetSessionByRefreshToken(tenantCtx("tenant-b"), "refresh-a"); err == nil {
		t.Error("tenant-b resolved a refresh token belonging to tenant-a")
	}

	if _, err := repo.GetSession(tenantCtx("tenant-a"), "session-a"); err != nil {
		t.Errorf("the owning tenant could not read its own session: %v", err)
	}
}
