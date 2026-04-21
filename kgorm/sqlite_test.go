package kgorm

import (
	"context"
	"testing"
	"time"

	"github.com/getkayan/kayan/core/audit"
	"github.com/getkayan/kayan/core/domain"
	"github.com/getkayan/kayan/core/identity"
	"github.com/getkayan/kayan/core/oauth2"
	"github.com/getkayan/kayan/core/rebac"
	"github.com/glebarez/sqlite"
	"gorm.io/gorm"
)

func setupSQLiteDB(t *testing.T) *gorm.DB {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	return db
}

func setupRepo(t *testing.T) *Repository {
	t.Helper()
	db := setupSQLiteDB(t)
	repo := NewRepository(db)
	if err := repo.AutoMigrate(); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	return repo
}

// --- Identity CRUD ---

func TestSQLite_CreateAndGetIdentity(t *testing.T) {
	repo := setupRepo(t)

	ident := &gormIdentity{
		ID:     "id-1",
		Traits: []byte(`{"email":"alice@example.com"}`),
		State:  "active",
	}
	if err := repo.CreateIdentity(ident); err != nil {
		t.Fatalf("CreateIdentity: %v", err)
	}

	factory := func() any { return &gormIdentity{} }
	got, err := repo.GetIdentity(factory, "id-1")
	if err != nil {
		t.Fatalf("GetIdentity: %v", err)
	}
	gi := got.(*gormIdentity)
	if gi.ID != "id-1" {
		t.Fatalf("expected ID 'id-1', got %q", gi.ID)
	}
	if gi.State != "active" {
		t.Fatalf("expected State 'active', got %q", gi.State)
	}
}

func TestSQLite_FindIdentity(t *testing.T) {
	repo := setupRepo(t)

	repo.CreateIdentity(&gormIdentity{ID: "id-1", State: "active"})
	repo.CreateIdentity(&gormIdentity{ID: "id-2", State: "inactive"})

	factory := func() any { return &gormIdentity{} }
	got, err := repo.FindIdentity(factory, map[string]any{"state": "inactive"})
	if err != nil {
		t.Fatalf("FindIdentity: %v", err)
	}
	gi := got.(*gormIdentity)
	if gi.ID != "id-2" {
		t.Fatalf("expected ID 'id-2', got %q", gi.ID)
	}
}

func TestSQLite_ListIdentities(t *testing.T) {
	repo := setupRepo(t)

	for i := 0; i < 5; i++ {
		repo.CreateIdentity(&gormIdentity{ID: "id-" + string(rune('A'+i)), State: "active"})
	}

	factory := func() any { return &gormIdentity{} }
	results, err := repo.ListIdentities(factory, 1, 3)
	if err != nil {
		t.Fatalf("ListIdentities: %v", err)
	}
	if len(results) != 3 {
		t.Fatalf("expected 3 identities, got %d", len(results))
	}
}

func TestSQLite_UpdateIdentity(t *testing.T) {
	repo := setupRepo(t)

	repo.CreateIdentity(&gormIdentity{ID: "id-1", State: "active"})

	factory := func() any { return &gormIdentity{} }
	got, _ := repo.GetIdentity(factory, "id-1")
	gi := got.(*gormIdentity)
	gi.State = "disabled"

	if err := repo.UpdateIdentity(gi); err != nil {
		t.Fatalf("UpdateIdentity: %v", err)
	}

	got, _ = repo.GetIdentity(factory, "id-1")
	gi = got.(*gormIdentity)
	if gi.State != "disabled" {
		t.Fatalf("expected State 'disabled', got %q", gi.State)
	}
}

func TestSQLite_DeleteIdentity(t *testing.T) {
	repo := setupRepo(t)

	repo.CreateIdentity(&gormIdentity{ID: "id-1", State: "active"})

	factory := func() any { return &gormIdentity{} }
	if err := repo.DeleteIdentity(factory, "id-1"); err != nil {
		t.Fatalf("DeleteIdentity: %v", err)
	}

	_, err := repo.GetIdentity(factory, "id-1")
	if err == nil {
		t.Fatal("expected error after delete")
	}
}

func TestSQLite_GetIdentity_NotFound(t *testing.T) {
	repo := setupRepo(t)

	factory := func() any { return &gormIdentity{} }
	_, err := repo.GetIdentity(factory, "nonexistent")
	if err == nil {
		t.Fatal("expected error for nonexistent identity")
	}
}

// --- Credential Operations ---

func TestSQLite_CreateAndGetCredential(t *testing.T) {
	repo := setupRepo(t)

	// Create identity first (foreign key)
	repo.CreateIdentity(&gormIdentity{ID: "id-1", State: "active"})

	cred := &gormCredential{
		ID:         "cred-1",
		IdentityID: "id-1",
		Type:       "password",
		Identifier: "alice@example.com",
		Secret:     "$2a$10$hashedpassword",
	}
	if err := repo.CreateCredential(cred); err != nil {
		t.Fatalf("CreateCredential: %v", err)
	}

	got, err := repo.GetCredentialByIdentifier("alice@example.com", "password")
	if err != nil {
		t.Fatalf("GetCredentialByIdentifier: %v", err)
	}
	if got.IdentityID != "id-1" {
		t.Fatalf("expected IdentityID 'id-1', got %q", got.IdentityID)
	}
}

func TestSQLite_UpdateCredentialSecret(t *testing.T) {
	repo := setupRepo(t)

	repo.CreateIdentity(&gormIdentity{ID: "id-1", State: "active"})
	repo.CreateCredential(&gormCredential{
		ID: "cred-1", IdentityID: "id-1", Type: "password",
		Identifier: "alice@example.com", Secret: "old-hash",
	})

	ctx := context.Background()
	if err := repo.UpdateCredentialSecret(ctx, "id-1", "password", "new-hash"); err != nil {
		t.Fatalf("UpdateCredentialSecret: %v", err)
	}

	got, _ := repo.GetCredentialByIdentifier("alice@example.com", "password")
	if got.Secret != "new-hash" {
		t.Fatalf("expected updated secret 'new-hash', got %q", got.Secret)
	}
}

func TestSQLite_GetCredentialByIdentifier_NotFound(t *testing.T) {
	repo := setupRepo(t)

	_, err := repo.GetCredentialByIdentifier("nobody@example.com", "password")
	if err == nil {
		t.Fatal("expected error for nonexistent credential")
	}
}

// --- Session Lifecycle ---

func TestSQLite_SessionCRUD(t *testing.T) {
	repo := setupRepo(t)

	sess := &identity.Session{
		ID:               "sess-1",
		IdentityID:       "id-1",
		RefreshToken:     "rt-abc",
		ExpiresAt:        time.Now().Add(1 * time.Hour).Truncate(time.Second),
		RefreshExpiresAt: time.Now().Add(24 * time.Hour).Truncate(time.Second),
		IssuedAt:         time.Now().Truncate(time.Second),
		Active:           true,
	}

	if err := repo.CreateSession(sess); err != nil {
		t.Fatalf("CreateSession: %v", err)
	}

	got, err := repo.GetSession("sess-1")
	if err != nil {
		t.Fatalf("GetSession: %v", err)
	}
	if got.IdentityID != "id-1" {
		t.Fatalf("expected IdentityID 'id-1', got %q", got.IdentityID)
	}
	if !got.Active {
		t.Fatal("expected session to be active")
	}

	// Get by refresh token
	got, err = repo.GetSessionByRefreshToken("rt-abc")
	if err != nil {
		t.Fatalf("GetSessionByRefreshToken: %v", err)
	}
	if got.ID != "sess-1" {
		t.Fatalf("expected session ID 'sess-1', got %q", got.ID)
	}

	// Delete
	if err := repo.DeleteSession("sess-1"); err != nil {
		t.Fatalf("DeleteSession: %v", err)
	}
	_, err = repo.GetSession("sess-1")
	if err == nil {
		t.Fatal("expected error after session delete")
	}
}

// --- OAuth2 Operations ---

func TestSQLite_OAuth2ClientCRUD(t *testing.T) {
	repo := setupRepo(t)
	ctx := context.Background()

	client := &oauth2.Client{
		ID:           "client-1",
		Secret:       "secret-hash",
		RedirectURIs: []string{"https://example.com/callback"},
		GrantTypes:   []string{"authorization_code"},
		Scopes:       []string{"openid", "profile"},
		AppName:      "Test App",
	}

	if err := repo.CreateClient(ctx, client); err != nil {
		t.Fatalf("CreateClient: %v", err)
	}

	got, err := repo.GetClient(ctx, "client-1")
	if err != nil {
		t.Fatalf("GetClient: %v", err)
	}
	if got.AppName != "Test App" {
		t.Fatalf("expected AppName 'Test App', got %q", got.AppName)
	}
	if len(got.Scopes) != 2 {
		t.Fatalf("expected 2 scopes, got %d", len(got.Scopes))
	}

	// List
	clients, err := repo.ListClients(ctx)
	if err != nil {
		t.Fatalf("ListClients: %v", err)
	}
	if len(clients) != 1 {
		t.Fatalf("expected 1 client, got %d", len(clients))
	}

	// Delete
	if err := repo.DeleteClient(ctx, "client-1"); err != nil {
		t.Fatalf("DeleteClient: %v", err)
	}
	_, err = repo.GetClient(ctx, "client-1")
	if err == nil {
		t.Fatal("expected error after client delete")
	}
}

func TestSQLite_OAuth2AuthCode(t *testing.T) {
	repo := setupRepo(t)
	ctx := context.Background()

	code := &oauth2.AuthCode{
		Code:                "code-abc",
		ClientID:            "client-1",
		IdentityID:          "id-1",
		RedirectURI:         "https://example.com/callback",
		Scopes:              []string{"openid"},
		CodeChallenge:       "challenge123",
		CodeChallengeMethod: "S256",
		ExpiresAt:           time.Now().Add(10 * time.Minute),
	}

	if err := repo.SaveAuthCode(ctx, code); err != nil {
		t.Fatalf("SaveAuthCode: %v", err)
	}

	got, err := repo.GetAuthCode(ctx, "code-abc")
	if err != nil {
		t.Fatalf("GetAuthCode: %v", err)
	}
	if got.ClientID != "client-1" {
		t.Fatalf("expected ClientID 'client-1', got %q", got.ClientID)
	}
	if got.CodeChallenge != "challenge123" {
		t.Fatalf("expected CodeChallenge 'challenge123', got %q", got.CodeChallenge)
	}

	if err := repo.DeleteAuthCode(ctx, "code-abc"); err != nil {
		t.Fatalf("DeleteAuthCode: %v", err)
	}
	_, err = repo.GetAuthCode(ctx, "code-abc")
	if err == nil {
		t.Fatal("expected error after auth code delete")
	}
}

func TestSQLite_OAuth2RefreshToken(t *testing.T) {
	repo := setupRepo(t)
	ctx := context.Background()

	rt := &oauth2.RefreshToken{
		Token:      "rt-xyz",
		ClientID:   "client-1",
		IdentityID: "id-1",
		Scopes:     []string{"openid", "offline_access"},
		ExpiresAt:  time.Now().Add(30 * 24 * time.Hour),
	}

	if err := repo.SaveRefreshToken(ctx, rt); err != nil {
		t.Fatalf("SaveRefreshToken: %v", err)
	}

	got, err := repo.GetRefreshToken(ctx, "rt-xyz")
	if err != nil {
		t.Fatalf("GetRefreshToken: %v", err)
	}
	if len(got.Scopes) != 2 {
		t.Fatalf("expected 2 scopes, got %d", len(got.Scopes))
	}

	if err := repo.DeleteRefreshToken(ctx, "rt-xyz"); err != nil {
		t.Fatalf("DeleteRefreshToken: %v", err)
	}
	_, err = repo.GetRefreshToken(ctx, "rt-xyz")
	if err == nil {
		t.Fatal("expected error after refresh token delete")
	}
}

// --- Token Store ---

func TestSQLite_TokenStore(t *testing.T) {
	repo := setupRepo(t)
	ctx := context.Background()

	token := &domain.AuthToken{
		Token:      "tok-abc",
		IdentityID: "id-1",
		Type:       "recovery",
		ExpiresAt:  time.Now().Add(1 * time.Hour),
	}

	if err := repo.SaveToken(ctx, token); err != nil {
		t.Fatalf("SaveToken: %v", err)
	}

	got, err := repo.GetToken(ctx, "tok-abc")
	if err != nil {
		t.Fatalf("GetToken: %v", err)
	}
	if got.Type != "recovery" {
		t.Fatalf("expected Type 'recovery', got %q", got.Type)
	}

	if err := repo.DeleteToken(ctx, "tok-abc"); err != nil {
		t.Fatalf("DeleteToken: %v", err)
	}
	_, err = repo.GetToken(ctx, "tok-abc")
	if err == nil {
		t.Fatal("expected error after token delete")
	}
}

func TestSQLite_DeleteExpiredTokens(t *testing.T) {
	repo := setupRepo(t)
	ctx := context.Background()

	// Create one expired and one valid token
	repo.SaveToken(ctx, &domain.AuthToken{
		Token: "expired-1", IdentityID: "id-1", Type: "recovery",
		ExpiresAt: time.Now().Add(-1 * time.Hour),
	})
	repo.SaveToken(ctx, &domain.AuthToken{
		Token: "valid-1", IdentityID: "id-1", Type: "recovery",
		ExpiresAt: time.Now().Add(1 * time.Hour),
	})

	if err := repo.DeleteExpiredTokens(ctx); err != nil {
		t.Fatalf("DeleteExpiredTokens: %v", err)
	}

	// Expired should be gone
	_, err := repo.GetToken(ctx, "expired-1")
	if err == nil {
		t.Fatal("expected expired token to be deleted")
	}

	// Valid should still exist
	got, err := repo.GetToken(ctx, "valid-1")
	if err != nil {
		t.Fatalf("expected valid token to still exist: %v", err)
	}
	if got.Token != "valid-1" {
		t.Fatalf("expected token 'valid-1', got %q", got.Token)
	}
}

// --- Audit Events ---

func TestSQLite_AuditEventLifecycle(t *testing.T) {
	repo := setupRepo(t)
	ctx := context.Background()

	event := &audit.AuditEvent{
		Type:      audit.EventLoginSuccess,
		ActorID:   "actor-1",
		Status:    "success",
		Message:   "login ok",
		CreatedAt: time.Now().Add(-2 * time.Hour),
	}
	if err := repo.SaveEvent(ctx, event); err != nil {
		t.Fatalf("SaveEvent: %v", err)
	}

	results, err := repo.Query(ctx, audit.Filter{ActorID: "actor-1"})
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}

	count, err := repo.Count(ctx, audit.Filter{ActorID: "actor-1"})
	if err != nil {
		t.Fatalf("Count: %v", err)
	}
	if count != 1 {
		t.Fatalf("expected count 1, got %d", count)
	}

	purged, err := repo.Purge(ctx, time.Now())
	if err != nil {
		t.Fatalf("Purge: %v", err)
	}
	if purged != 1 {
		t.Fatalf("expected 1 purged, got %d", purged)
	}
}

// --- RBAC Repository ---

func TestSQLite_RBAC(t *testing.T) {
	db := setupSQLiteDB(t)
	if err := db.AutoMigrate(&RoleAssignment{}); err != nil {
		t.Fatalf("migrate RBAC: %v", err)
	}
	rbacRepo := NewRBACRepository(db)

	// Initially no roles
	roles, err := rbacRepo.GetIdentityRoles("id-1")
	if err != nil {
		t.Fatalf("GetIdentityRoles: %v", err)
	}
	if len(roles) != 0 {
		t.Fatalf("expected 0 roles, got %d", len(roles))
	}

	// Set roles
	if err := rbacRepo.SetIdentityRoles("id-1", []string{"admin", "editor"}); err != nil {
		t.Fatalf("SetIdentityRoles: %v", err)
	}
	roles, _ = rbacRepo.GetIdentityRoles("id-1")
	if len(roles) != 2 {
		t.Fatalf("expected 2 roles, got %d", len(roles))
	}

	// Replace roles
	if err := rbacRepo.SetIdentityRoles("id-1", []string{"viewer"}); err != nil {
		t.Fatalf("SetIdentityRoles replace: %v", err)
	}
	roles, _ = rbacRepo.GetIdentityRoles("id-1")
	if len(roles) != 1 {
		t.Fatalf("expected 1 role after replace, got %d", len(roles))
	}
	if roles[0] != "viewer" {
		t.Fatalf("expected role 'viewer', got %q", roles[0])
	}

	// Clear all roles
	if err := rbacRepo.SetIdentityRoles("id-1", nil); err != nil {
		t.Fatalf("SetIdentityRoles clear: %v", err)
	}
	roles, _ = rbacRepo.GetIdentityRoles("id-1")
	if len(roles) != 0 {
		t.Fatalf("expected 0 roles after clear, got %d", len(roles))
	}
}

// --- ReBAC Repository ---

func TestSQLite_ReBAC(t *testing.T) {
	db := setupSQLiteDB(t)
	rebacRepo := NewReBACRepository(db)
	if err := rebacRepo.AutoMigrate(); err != nil {
		t.Fatalf("migrate ReBAC: %v", err)
	}
	ctx := context.Background()

	tuple := rebac.Tuple{
		Subject:  rebac.SubjectRef{Object: rebac.ObjectRef{Type: "user", ID: "alice"}},
		Relation: "viewer",
		Object:   rebac.ObjectRef{Type: "document", ID: "doc-1"},
	}

	// Write
	if err := rebacRepo.WriteTuple(ctx, tuple); err != nil {
		t.Fatalf("WriteTuple: %v", err)
	}

	// Exists
	exists, err := rebacRepo.TupleExists(ctx, tuple)
	if err != nil {
		t.Fatalf("TupleExists: %v", err)
	}
	if !exists {
		t.Fatal("expected tuple to exist")
	}

	// Read
	tuples, err := rebacRepo.ReadTuples(ctx, rebac.TupleFilter{
		ObjectType: "document",
		ObjectID:   "doc-1",
	})
	if err != nil {
		t.Fatalf("ReadTuples: %v", err)
	}
	if len(tuples) != 1 {
		t.Fatalf("expected 1 tuple, got %d", len(tuples))
	}

	// Write batch
	if err := rebacRepo.WriteTuples(ctx, []rebac.Tuple{
		{
			Subject:  rebac.SubjectRef{Object: rebac.ObjectRef{Type: "user", ID: "bob"}},
			Relation: "editor",
			Object:   rebac.ObjectRef{Type: "document", ID: "doc-1"},
		},
	}); err != nil {
		t.Fatalf("WriteTuples: %v", err)
	}

	tuples, _ = rebacRepo.ReadTuples(ctx, rebac.TupleFilter{ObjectType: "document", ObjectID: "doc-1"})
	if len(tuples) != 2 {
		t.Fatalf("expected 2 tuples, got %d", len(tuples))
	}

	// Delete
	if err := rebacRepo.DeleteTuple(ctx, tuple); err != nil {
		t.Fatalf("DeleteTuple: %v", err)
	}
	exists, _ = rebacRepo.TupleExists(ctx, tuple)
	if exists {
		t.Fatal("expected tuple to be deleted")
	}

	// Delete with filter
	if err := rebacRepo.DeleteTuples(ctx, rebac.TupleFilter{ObjectType: "document", ObjectID: "doc-1"}); err != nil {
		t.Fatalf("DeleteTuples: %v", err)
	}
	tuples, _ = rebacRepo.ReadTuples(ctx, rebac.TupleFilter{ObjectType: "document", ObjectID: "doc-1"})
	if len(tuples) != 0 {
		t.Fatalf("expected 0 tuples after filter delete, got %d", len(tuples))
	}
}

// --- Registry ---

func TestSQLite_Registry_NewStorage(t *testing.T) {
	storage, err := NewStorage("sqlite", ":memory:", nil)
	if err != nil {
		t.Fatalf("NewStorage: %v", err)
	}
	if storage == nil {
		t.Fatal("expected non-nil storage")
	}
}
