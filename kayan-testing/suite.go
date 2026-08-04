package kayantesting

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"testing"
	"time"

	"github.com/getkayan/kayan/core/domain"
	"github.com/getkayan/kayan/core/identity"
)

// SuiteIdentity is the identity model the contract suite stores.
//
// It is deliberately plain: any [domain.Storage] must handle an arbitrary
// caller-defined struct, which is what "bring your own schema" means.
type SuiteIdentity struct {
	ID    string
	Email string
	Name  string
	State string
}

// GetID satisfies the identity contract used by the flow packages.
func (u *SuiteIdentity) GetID() any { return u.ID }

// SetID satisfies the identity contract used by the flow packages.
func (u *SuiteIdentity) SetID(id any) {
	if s, ok := id.(string); ok {
		u.ID = s
	}
}

// StorageSuite runs the [domain.Storage] contract against an implementation.
//
// newStore must return a fresh, empty store on each call; the suite calls it
// once per subtest so failures cannot cascade.
//
//	func TestMyStore(t *testing.T) {
//	    kayantesting.StorageSuite(t, func() domain.Storage {
//	        return mystore.New(...)
//	    })
//	}
//
// A store that needs schema prepared for the caller's identity model — a SQL
// adapter, say — should migrate [SuiteIdentity] inside newStore, or use
// [StorageSuiteWithModel] to supply its own model:
//
//	kayantesting.StorageSuite(t, func() domain.Storage {
//	    db := openTestDB(t)
//	    if err := db.AutoMigrate(&kayantesting.SuiteIdentity{}); err != nil {
//	        t.Fatal(err)
//	    }
//	    return gormstore.New(db)
//	})
//
// The suite asserts behavior the rest of Kayan depends on. It deliberately
// does not assert error identity — adapters return their own error values —
// only whether an operation succeeds or fails.
func StorageSuite(t *testing.T, newStore func() domain.Storage) {
	t.Helper()
	StorageSuiteWithModel(t, newStore, func() any { return &SuiteIdentity{} })
}

// StorageSuiteWithModel is [StorageSuite] for a store whose identity model is
// not [SuiteIdentity].
//
// The model must have string fields named ID, Email, and Name, since the suite
// reads and queries those. Use this when the adapter can only persist a type
// it already knows, such as one carrying database struct tags.
func StorageSuiteWithModel(t *testing.T, newStore func() domain.Storage, factory func() any) {
	t.Helper()

	if err := checkModel(factory); err != nil {
		t.Fatalf("identity model is unusable: %v", err)
	}

	t.Run("Identity", func(t *testing.T) { suiteIdentity(t, newStore, factory) })
	t.Run("Credential", func(t *testing.T) { suiteCredential(t, newStore) })
	t.Run("Session", func(t *testing.T) { suiteSession(t, newStore) })
	t.Run("Token", func(t *testing.T) { suiteToken(t, newStore) })
}

// checkModel reports whether the factory yields a struct the suite can drive.
func checkModel(factory func() any) error {
	if factory == nil {
		return errors.New("factory is nil")
	}
	model := factory()
	if model == nil {
		return errors.New("factory returned nil")
	}

	v := reflect.ValueOf(model)
	if v.Kind() != reflect.Ptr || v.IsNil() {
		return fmt.Errorf("factory returned %T, want a non-nil pointer to a struct", model)
	}
	v = v.Elem()
	if v.Kind() != reflect.Struct {
		return fmt.Errorf("factory returned a pointer to %s, want a struct", v.Kind())
	}

	for _, name := range []string{"ID", "Email", "Name"} {
		f := v.FieldByName(name)
		if !f.IsValid() {
			return fmt.Errorf("model %T has no field %s", model, name)
		}
		if f.Kind() != reflect.String {
			return fmt.Errorf("model %T field %s is %s, want string", model, name, f.Kind())
		}
	}
	return nil
}

// newIdentity builds an identity from the caller's model and sets the fields
// the suite asserts on.
func newIdentity(t *testing.T, factory func() any, id, email, name string) any {
	t.Helper()

	model := factory()
	v := reflect.ValueOf(model).Elem()
	for field, value := range map[string]string{"ID": id, "Email": email, "Name": name} {
		if value == "" {
			continue
		}
		v.FieldByName(field).SetString(value)
	}
	return model
}

// identityField reads a string field from an identity of the caller's model.
func identityField(t *testing.T, ident any, field string) string {
	t.Helper()

	v := reflect.ValueOf(ident)
	for v.Kind() == reflect.Ptr {
		if v.IsNil() {
			t.Fatalf("identity is a nil %T", ident)
		}
		v = v.Elem()
	}
	f := v.FieldByName(field)
	if !f.IsValid() {
		t.Fatalf("identity %T has no field %s", ident, field)
	}
	return f.String()
}

func suiteIdentity(t *testing.T, newStore func() domain.Storage, factory func() any) {
	t.Helper()

	t.Run("create then get", func(t *testing.T) {
		ctx := context.Background()
		store := newStore()
		want := newIdentity(t, factory, "u1", "a@example.test", "A")

		if err := store.CreateIdentity(ctx, want); err != nil {
			t.Fatalf("CreateIdentity: %v", err)
		}

		got, err := store.GetIdentity(ctx, factory, "u1")
		if err != nil {
			t.Fatalf("GetIdentity: %v", err)
		}
		if email := identityField(t, got, "Email"); email != "a@example.test" {
			t.Errorf("Email = %q, want a@example.test", email)
		}
	})

	t.Run("get missing reports an error", func(t *testing.T) {
		ctx := context.Background()
		store := newStore()
		if _, err := store.GetIdentity(ctx, factory, "nope"); err == nil {
			t.Error("GetIdentity returned no error for a missing identity")
		}
	})

	t.Run("find by field", func(t *testing.T) {
		ctx := context.Background()
		store := newStore()
		if err := store.CreateIdentity(ctx, newIdentity(t, factory, "u1", "find@example.test", "")); err != nil {
			t.Fatalf("CreateIdentity: %v", err)
		}

		got, err := store.FindIdentity(ctx, factory, map[string]any{"Email": "find@example.test"})
		if err != nil {
			t.Fatalf("FindIdentity: %v", err)
		}
		if id := identityField(t, got, "ID"); id != "u1" {
			t.Errorf("ID = %q, want u1", id)
		}
	})

	t.Run("find with no match reports an error", func(t *testing.T) {
		ctx := context.Background()
		store := newStore()
		if err := store.CreateIdentity(ctx, newIdentity(t, factory, "u1", "a@example.test", "")); err != nil {
			t.Fatalf("CreateIdentity: %v", err)
		}
		if _, err := store.FindIdentity(ctx, factory, map[string]any{"Email": "absent@example.test"}); err == nil {
			t.Error("FindIdentity returned no error for a query matching nothing")
		}
	})

	t.Run("find requires every field to match", func(t *testing.T) {
		ctx := context.Background()
		store := newStore()
		if err := store.CreateIdentity(ctx, newIdentity(t, factory, "u1", "a@example.test", "A")); err != nil {
			t.Fatalf("CreateIdentity: %v", err)
		}
		// Email matches, Name does not: the identity must not be returned.
		_, err := store.FindIdentity(ctx, factory, map[string]any{
			"Email": "a@example.test",
			"Name":  "different",
		})
		if err == nil {
			t.Error("FindIdentity matched on a partial query; all fields must match")
		}
	})

	t.Run("update", func(t *testing.T) {
		ctx := context.Background()
		store := newStore()
		user := newIdentity(t, factory, "u1", "before@example.test", "")
		if err := store.CreateIdentity(ctx, user); err != nil {
			t.Fatalf("CreateIdentity: %v", err)
		}

		reflect.ValueOf(user).Elem().FieldByName("Email").SetString("after@example.test")
		if err := store.UpdateIdentity(ctx, user); err != nil {
			t.Fatalf("UpdateIdentity: %v", err)
		}

		got, err := store.GetIdentity(ctx, factory, "u1")
		if err != nil {
			t.Fatalf("GetIdentity: %v", err)
		}
		if email := identityField(t, got, "Email"); email != "after@example.test" {
			t.Errorf("Email = %q, want after@example.test", email)
		}
	})

	t.Run("delete", func(t *testing.T) {
		ctx := context.Background()
		store := newStore()
		if err := store.CreateIdentity(ctx, newIdentity(t, factory, "u1", "", "")); err != nil {
			t.Fatalf("CreateIdentity: %v", err)
		}
		if err := store.DeleteIdentity(ctx, factory, "u1"); err != nil {
			t.Fatalf("DeleteIdentity: %v", err)
		}
		if _, err := store.GetIdentity(ctx, factory, "u1"); err == nil {
			t.Error("identity is still readable after deletion")
		}
	})

	t.Run("list paginates", func(t *testing.T) {
		ctx := context.Background()
		store := newStore()
		const total = 5
		for i := range total {
			id := string(rune('a' + i))
			if err := store.CreateIdentity(ctx, newIdentity(t, factory, id, id+"@example.test", "")); err != nil {
				t.Fatalf("CreateIdentity: %v", err)
			}
		}

		first, err := store.ListIdentities(ctx, factory, 1, 2)
		if err != nil {
			t.Fatalf("ListIdentities: %v", err)
		}
		if len(first) != 2 {
			t.Errorf("page 1 has %d identities, want 2", len(first))
		}

		// A page past the end must be empty, not an error.
		beyond, err := store.ListIdentities(ctx, factory, 99, 2)
		if err != nil {
			t.Fatalf("ListIdentities beyond the end: %v", err)
		}
		if len(beyond) != 0 {
			t.Errorf("page 99 has %d identities, want 0", len(beyond))
		}
	})
}

func suiteCredential(t *testing.T, newStore func() domain.Storage) {
	t.Helper()

	t.Run("create then look up", func(t *testing.T) {
		ctx := context.Background()
		store := newStore()
		cred := &identity.Credential{
			ID:         "c1",
			IdentityID: "u1",
			Type:       "password",
			Identifier: "user@example.test",
			Secret:     "hashed-secret",
		}
		if err := store.CreateCredential(ctx, cred); err != nil {
			t.Fatalf("CreateCredential: %v", err)
		}

		got, err := store.GetCredentialByIdentifier(ctx, "user@example.test", "password")
		if err != nil {
			t.Fatalf("GetCredentialByIdentifier: %v", err)
		}
		if got.Secret != "hashed-secret" {
			t.Errorf("Secret = %q, want hashed-secret", got.Secret)
		}
	})

	t.Run("method scopes the lookup", func(t *testing.T) {
		ctx := context.Background()
		store := newStore()
		if err := store.CreateCredential(ctx, &identity.Credential{
			ID: "c1", IdentityID: "u1", Type: "password", Identifier: "shared@example.test", Secret: "pw",
		}); err != nil {
			t.Fatalf("CreateCredential: %v", err)
		}

		// The same identifier under a different method must not be found.
		if _, err := store.GetCredentialByIdentifier(ctx, "shared@example.test", "totp"); err == nil {
			t.Error("credential was returned for the wrong method")
		}
	})

	t.Run("missing credential reports an error", func(t *testing.T) {
		ctx := context.Background()
		store := newStore()
		if _, err := store.GetCredentialByIdentifier(ctx, "absent@example.test", "password"); err == nil {
			t.Error("GetCredentialByIdentifier returned no error for a missing credential")
		}
	})

	t.Run("update secret", func(t *testing.T) {
		ctx := context.Background()
		store := newStore()
		if err := store.CreateCredential(ctx, &identity.Credential{
			ID: "c1", IdentityID: "u1", Type: "password", Identifier: "user@example.test", Secret: "old",
		}); err != nil {
			t.Fatalf("CreateCredential: %v", err)
		}

		if err := store.UpdateCredentialSecret(ctx, "u1", "password", "new"); err != nil {
			t.Fatalf("UpdateCredentialSecret: %v", err)
		}

		got, err := store.GetCredentialByIdentifier(ctx, "user@example.test", "password")
		if err != nil {
			t.Fatalf("GetCredentialByIdentifier: %v", err)
		}
		if got.Secret != "new" {
			t.Errorf("Secret = %q, want new", got.Secret)
		}
	})
}

func suiteSession(t *testing.T, newStore func() domain.Storage) {
	t.Helper()

	newSession := func() *identity.Session {
		return &identity.Session{
			ID:           "s1",
			IdentityID:   "u1",
			RefreshToken: "refresh-token",
			ExpiresAt:    time.Now().Add(time.Hour),
			IssuedAt:     time.Now(),
			Active:       true,
		}
	}

	t.Run("create then get", func(t *testing.T) {
		ctx := context.Background()
		store := newStore()
		if err := store.CreateSession(ctx, newSession()); err != nil {
			t.Fatalf("CreateSession: %v", err)
		}

		got, err := store.GetSession(ctx, "s1")
		if err != nil {
			t.Fatalf("GetSession: %v", err)
		}
		if got.IdentityID != "u1" {
			t.Errorf("IdentityID = %q, want u1", got.IdentityID)
		}
	})

	t.Run("get by refresh token", func(t *testing.T) {
		ctx := context.Background()
		store := newStore()
		if err := store.CreateSession(ctx, newSession()); err != nil {
			t.Fatalf("CreateSession: %v", err)
		}

		got, err := store.GetSessionByRefreshToken(ctx, "refresh-token")
		if err != nil {
			t.Fatalf("GetSessionByRefreshToken: %v", err)
		}
		if got.ID != "s1" {
			t.Errorf("ID = %q, want s1", got.ID)
		}
	})

	t.Run("delete", func(t *testing.T) {
		ctx := context.Background()
		store := newStore()
		if err := store.CreateSession(ctx, newSession()); err != nil {
			t.Fatalf("CreateSession: %v", err)
		}
		if err := store.DeleteSession(ctx, "s1"); err != nil {
			t.Fatalf("DeleteSession: %v", err)
		}
		if _, err := store.GetSession(ctx, "s1"); err == nil {
			t.Error("session is still readable after deletion")
		}
		// The refresh-token index must not outlive the session, or a deleted
		// session stays refreshable.
		if _, err := store.GetSessionByRefreshToken(ctx, "refresh-token"); err == nil {
			t.Error("refresh token still resolves after the session was deleted")
		}
	})

	t.Run("missing session reports an error", func(t *testing.T) {
		ctx := context.Background()
		store := newStore()
		if _, err := store.GetSession(ctx, "absent"); err == nil {
			t.Error("GetSession returned no error for a missing session")
		}
	})
}

func suiteToken(t *testing.T, newStore func() domain.Storage) {
	t.Helper()

	t.Run("save then get", func(t *testing.T) {
		ctx := context.Background()
		store := newStore()
		token := &domain.AuthToken{
			Token:      "tok-1",
			IdentityID: "u1",
			Type:       "recovery",
			ExpiresAt:  time.Now().Add(time.Hour),
		}
		if err := store.SaveToken(ctx, token); err != nil {
			t.Fatalf("SaveToken: %v", err)
		}

		got, err := store.GetToken(ctx, "tok-1")
		if err != nil {
			t.Fatalf("GetToken: %v", err)
		}
		if got.IdentityID != "u1" {
			t.Errorf("IdentityID = %q, want u1", got.IdentityID)
		}
	})

	t.Run("delete", func(t *testing.T) {
		ctx := context.Background()
		store := newStore()
		if err := store.SaveToken(ctx, &domain.AuthToken{
			Token: "tok-1", IdentityID: "u1", Type: "recovery", ExpiresAt: time.Now().Add(time.Hour),
		}); err != nil {
			t.Fatalf("SaveToken: %v", err)
		}
		if err := store.DeleteToken(ctx, "tok-1"); err != nil {
			t.Fatalf("DeleteToken: %v", err)
		}
		if _, err := store.GetToken(ctx, "tok-1"); err == nil {
			t.Error("token is still readable after deletion")
		}
	})

	t.Run("expired token is not returned", func(t *testing.T) {
		ctx := context.Background()
		store := newStore()
		if err := store.SaveToken(ctx, &domain.AuthToken{
			Token: "expired", IdentityID: "u1", Type: "recovery",
			ExpiresAt: time.Now().Add(-time.Hour),
		}); err != nil {
			t.Fatalf("SaveToken: %v", err)
		}
		// An expired token must never be handed back: it is a live credential
		// for password recovery and magic-link login.
		if _, err := store.GetToken(ctx, "expired"); err == nil {
			t.Error("an expired token was returned")
		}
	})

	t.Run("delete expired sweeps only expired tokens", func(t *testing.T) {
		ctx := context.Background()
		store := newStore()
		if err := store.SaveToken(ctx, &domain.AuthToken{
			Token: "live", IdentityID: "u1", Type: "recovery", ExpiresAt: time.Now().Add(time.Hour),
		}); err != nil {
			t.Fatalf("SaveToken: %v", err)
		}
		if err := store.SaveToken(ctx, &domain.AuthToken{
			Token: "dead", IdentityID: "u1", Type: "recovery", ExpiresAt: time.Now().Add(-time.Hour),
		}); err != nil {
			t.Fatalf("SaveToken: %v", err)
		}

		if err := store.DeleteExpiredTokens(ctx); err != nil {
			t.Fatalf("DeleteExpiredTokens: %v", err)
		}
		if _, err := store.GetToken(ctx, "live"); err != nil {
			t.Errorf("a live token was swept: %v", err)
		}
	})
}
