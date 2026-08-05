package flow

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/getkayan/kayan/core/identity"
	"github.com/go-webauthn/webauthn/webauthn"
)

func TestNewWebAuthnStrategy(t *testing.T) {
	sessionStore := NewMemoryWebAuthnSessionStore()

	config := WebAuthnConfig{
		RPDisplayName: "Test App",
		RPID:          "localhost",
		RPOrigins:     []string{"http://localhost:8080"},
	}

	strategy, err := NewWebAuthnStrategy(nil, config, nil, sessionStore)
	if err != nil {
		t.Fatalf("Failed to create WebAuthn strategy: %v", err)
	}

	if strategy.ID() != "webauthn" {
		t.Errorf("Expected ID 'webauthn', got '%s'", strategy.ID())
	}
}

func TestMemoryWebAuthnSessionStore(t *testing.T) {
	store := NewMemoryWebAuthnSessionStore()
	ctx := context.Background()

	sessionData := &WebAuthnSessionData{
		Challenge:        "test-challenge",
		UserID:           []byte("user-123"),
		UserVerification: "preferred",
	}

	// Test SaveSession
	err := store.SaveSession(ctx, "session-1", sessionData)
	if err != nil {
		t.Fatalf("SaveSession failed: %v", err)
	}

	// Test GetSession
	retrieved, err := store.GetSession(ctx, "session-1")
	if err != nil {
		t.Fatalf("GetSession failed: %v", err)
	}

	if retrieved.Challenge != sessionData.Challenge {
		t.Errorf("Challenge mismatch: expected %s, got %s", sessionData.Challenge, retrieved.Challenge)
	}

	// Test GetSession for non-existent session
	_, err = store.GetSession(ctx, "non-existent")
	if err == nil {
		t.Error("Expected error for non-existent session")
	}

	// Test DeleteSession
	err = store.DeleteSession(ctx, "session-1")
	if err != nil {
		t.Fatalf("DeleteSession failed: %v", err)
	}

	_, err = store.GetSession(ctx, "session-1")
	if err == nil {
		t.Error("Expected error after deletion")
	}
}

func TestWebAuthnCredentialData(t *testing.T) {
	data := WebAuthnCredentialData{
		CredentialID:    []byte("cred-id"),
		PublicKey:       []byte("public-key"),
		AttestationType: "none",
		AAGUID:          []byte("aaguid"),
		SignCount:       0,
		CloneWarning:    false,
		BackupEligible:  true,
		BackupState:     false,
	}

	if string(data.CredentialID) != "cred-id" {
		t.Error("CredentialID mismatch")
	}

	if !data.BackupEligible {
		t.Error("BackupEligible should be true")
	}
}

// TestMemoryWebAuthnSessionStoreIsConcurrencySafe covers a data race: the store
// guarded its map with nothing at all, so two users in overlapping ceremonies —
// the normal case for any deployment with more than one user — could crash the
// process with a concurrent map write. Run with -race.
func TestMemoryWebAuthnSessionStoreIsConcurrencySafe(t *testing.T) {
	ctx := context.Background()
	store := NewMemoryWebAuthnSessionStore()

	var wg sync.WaitGroup
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			id := fmt.Sprintf("session-%d", i)
			data := &WebAuthnSessionData{
				Challenge: id,
				ExpiresAt: time.Now().Add(time.Minute),
			}
			if err := store.SaveSession(ctx, id, data); err != nil {
				t.Errorf("SaveSession: %v", err)
			}
			if _, err := store.GetSession(ctx, id); err != nil {
				t.Errorf("GetSession: %v", err)
			}
			if err := store.DeleteSession(ctx, id); err != nil {
				t.Errorf("DeleteSession: %v", err)
			}
		}(i)
	}
	wg.Wait()
}

// TestWebAuthnSetHooksIsConcurrencySafe covers the same class on the strategy:
// SetHooks wrote s.hooks with no lock while ceremonies read it.
func TestWebAuthnSetHooksIsConcurrencySafe(t *testing.T) {
	s := &WebAuthnStrategy{}

	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			s.SetHooks(WebAuthnHooks{AllowClonedAuthenticators: true})
		}()
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = s.getHooks()
		}()
	}
	wg.Wait()
}

// TestWebAuthnCloneWarningRefusesByDefault documents the decision the clone
// branch encodes. A backwards signature counter is the only signal WebAuthn
// gives that a credential has been copied out of its authenticator; the code
// persisted that flag and then returned the identity anyway, so the one
// detection mechanism in the protocol recorded the break-in and let it through.
//
// The counter behaviour itself belongs to go-webauthn and is not re-tested
// here — what is pinned is that the refusal is the default and the escape
// hatch must be set explicitly.
func TestWebAuthnCloneWarningRefusesByDefault(t *testing.T) {
	if (WebAuthnHooks{}).AllowClonedAuthenticators {
		t.Fatal("clone warnings are ignored by default")
	}

	s := &WebAuthnStrategy{}
	if s.getHooks().AllowClonedAuthenticators {
		t.Error("a strategy built with no hooks allows cloned authenticators")
	}
}

// newHookTestStrategy builds a strategy over the shared mock repo, with an
// identity that already carries one WebAuthn credential.
func newHookTestStrategy(t *testing.T, hooks WebAuthnHooks) (*WebAuthnStrategy, *mockRepo, *identity.Identity) {
	t.Helper()

	repo := &mockRepo{
		identities: make(map[string]any),
		creds:      make(map[string]*identity.Credential),
	}

	credConfig, err := json.Marshal(WebAuthnCredentialData{
		CredentialID: []byte("cred-1"),
		PublicKey:    []byte("key-1"),
	})
	if err != nil {
		t.Fatalf("marshal credential config: %v", err)
	}

	ident := &identity.Identity{
		ID: "user-1",
		Credentials: []identity.Credential{{
			ID:         "c1",
			IdentityID: "user-1",
			Type:       "webauthn",
			Identifier: "ada@example.com",
			Config:     identity.JSON(credConfig),
		}},
	}
	repo.identities["user-1"] = ident
	repo.creds["ada@example.com:"] = &ident.Credentials[0]

	strategy, err := NewWebAuthnStrategy(repo, WebAuthnConfig{
		RPDisplayName: "Test App",
		RPID:          "localhost",
		RPOrigins:     []string{"http://localhost:8080"},
		Hooks:         hooks,
	}, func() any { return &identity.Identity{} }, NewMemoryWebAuthnSessionStore())
	if err != nil {
		t.Fatalf("NewWebAuthnStrategy: %v", err)
	}
	return strategy, repo, ident
}

// TestWebAuthnGateHooksCanAbort proves the Before* hooks are actually consulted.
// Every field on WebAuthnHooks was declared and never invoked, so a caller who
// set one of these to enforce a policy got no enforcement and no indication
// that nothing had happened.
func TestWebAuthnGateHooksCanAbort(t *testing.T) {
	ctx := context.Background()
	sentinel := errors.New("refused by hook")

	for _, tc := range []struct {
		name  string
		hooks func(*bool) WebAuthnHooks
		call  func(*WebAuthnStrategy, any) error
	}{
		{
			name: "BeforeBeginRegistration",
			hooks: func(called *bool) WebAuthnHooks {
				return WebAuthnHooks{BeforeBeginRegistration: func(context.Context, any, string) error {
					*called = true
					return sentinel
				}}
			},
			call: func(s *WebAuthnStrategy, ident any) error {
				_, _, err := s.BeginRegistration(ctx, ident, "ada@example.com", "Ada")
				return err
			},
		},
		{
			name: "BeforeFinishRegistration",
			hooks: func(called *bool) WebAuthnHooks {
				return WebAuthnHooks{BeforeFinishRegistration: func(context.Context, any, string) error {
					*called = true
					return sentinel
				}}
			},
			call: func(s *WebAuthnStrategy, ident any) error {
				_, err := s.FinishRegistration(ctx, ident, "sess", "ada@example.com", "Ada", nil)
				return err
			},
		},
		{
			name: "BeforeBeginLogin",
			hooks: func(called *bool) WebAuthnHooks {
				return WebAuthnHooks{BeforeBeginLogin: func(context.Context, string) error {
					*called = true
					return sentinel
				}}
			},
			call: func(s *WebAuthnStrategy, ident any) error {
				_, _, err := s.BeginLogin(ctx, "ada@example.com")
				return err
			},
		},
		{
			name: "BeforeFinishLogin",
			hooks: func(called *bool) WebAuthnHooks {
				return WebAuthnHooks{BeforeFinishLogin: func(context.Context, string, string) error {
					*called = true
					return sentinel
				}}
			},
			call: func(s *WebAuthnStrategy, ident any) error {
				_, err := s.FinishLogin(ctx, "ada@example.com", "sess", nil)
				return err
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var called bool
			strategy, _, ident := newHookTestStrategy(t, tc.hooks(&called))

			err := tc.call(strategy, ident)
			if !called {
				t.Fatal("the hook was never invoked")
			}
			if !errors.Is(err, sentinel) {
				t.Errorf("error = %v, want the hook's error — the refusal was discarded", err)
			}
		})
	}
}

// TestWebAuthnUserLoaderReplacesLookup proves UserLoader is honoured. It
// documents itself as bypassing the default identifier-based lookup, which it
// did not do.
func TestWebAuthnUserLoaderReplacesLookup(t *testing.T) {
	ctx := context.Background()
	custom := &identity.Identity{ID: "loaded-by-hook"}

	var identifier string
	strategy, _, _ := newHookTestStrategy(t, WebAuthnHooks{
		UserLoader: func(_ context.Context, id string) (any, error) {
			identifier = id
			return custom, nil
		},
	})

	// The identifier is deliberately one the repo does not know, so a pass
	// through the default lookup would fail rather than silently succeed.
	got, err := strategy.loadUser(ctx, "nobody@example.com", strategy.getHooks())
	if err != nil {
		t.Fatalf("loadUser: %v", err)
	}
	if identifier != "nobody@example.com" {
		t.Errorf("hook received identifier %q", identifier)
	}
	if got != any(custom) {
		t.Errorf("got %v, want the identity the hook returned", got)
	}
}

// TestWebAuthnCreateSessionIDIsHonoured proves the ceremony uses the caller's
// session ID generator when one is supplied.
func TestWebAuthnCreateSessionIDIsHonoured(t *testing.T) {
	strategy, _, _ := newHookTestStrategy(t, WebAuthnHooks{
		CreateSessionID: func() string { return "session-from-hook" },
	})

	if got := strategy.newSessionID(strategy.getHooks()); got != "session-from-hook" {
		t.Errorf("session ID = %q, want the hook's value", got)
	}

	plain, _, _ := newHookTestStrategy(t, WebAuthnHooks{})
	if got := plain.newSessionID(plain.getHooks()); got == "" || got == "session-from-hook" {
		t.Errorf("default session ID = %q, want a generated one", got)
	}
}

// TestWebAuthnCredentialFilterExcludes proves CredentialFilter narrows the
// credential set offered during a ceremony. Returning false for every
// credential must leave none.
func TestWebAuthnCredentialFilterExcludes(t *testing.T) {
	_, _, ident := newHookTestStrategy(t, WebAuthnHooks{})

	unfiltered, _, _ := newHookTestStrategy(t, WebAuthnHooks{})
	if got := len(unfiltered.getExistingCredentials(ident)); got != 1 {
		t.Fatalf("credentials without a filter = %d, want 1", got)
	}

	var seen int
	filtered, _, _ := newHookTestStrategy(t, WebAuthnHooks{
		CredentialFilter: func(*identity.Credential) bool {
			seen++
			return false
		},
	})
	if got := len(filtered.getExistingCredentials(ident)); got != 0 {
		t.Errorf("credentials with a rejecting filter = %d, want 0", got)
	}
	if seen != 1 {
		t.Errorf("filter was called %d times, want 1", seen)
	}
}

// insertOnlyRepo rejects CreateIdentity for an ID that already exists, which is
// what a real database does and what mockRepo does not — it treats create and
// update as the same map write, so it cannot distinguish an insert from an
// update and never caught this.
type insertOnlyRepo struct {
	*mockRepo
	updates int
}

func (r *insertOnlyRepo) CreateIdentity(ctx context.Context, ident any) error {
	fi, ok := ident.(FlowIdentity)
	if !ok {
		return r.mockRepo.CreateIdentity(ctx, ident)
	}
	if _, exists := r.mockRepo.identities[fmt.Sprintf("%v", fi.GetID())]; exists {
		return errors.New("duplicate key: identity already exists")
	}
	return r.mockRepo.CreateIdentity(ctx, ident)
}

func (r *insertOnlyRepo) UpdateIdentity(ctx context.Context, ident any) error {
	r.updates++
	return r.mockRepo.UpdateIdentity(ctx, ident)
}

// fakeClock is a domain.Clock whose time only moves when told. core cannot
// import kayan-testing, so this is the local equivalent.
type fakeClock struct{ now time.Time }

func (c *fakeClock) Now() time.Time { return c.now }

// TestWebAuthnRegistrationUpdatesRatherThanInserts covers a write that could
// not succeed. FinishRegistration attaches a credential to an identity that
// already exists — BeginRegistration was handed one — but persisted it with
// CreateIdentity. On any storage that treats a create as an insert, enrolling
// a second passkey failed with a duplicate key after the ceremony had already
// succeeded, so the credential was lost.
func TestWebAuthnRegistrationUpdatesRatherThanInserts(t *testing.T) {
	ctx := context.Background()

	repo := &insertOnlyRepo{mockRepo: &mockRepo{
		identities: make(map[string]any),
		creds:      make(map[string]*identity.Credential),
	}}
	ident := &identity.Identity{ID: "user-1"}
	if err := repo.CreateIdentity(ctx, ident); err != nil {
		t.Fatalf("seed identity: %v", err)
	}

	strategy, err := NewWebAuthnStrategy(repo, WebAuthnConfig{
		RPDisplayName: "Test App",
		RPID:          "localhost",
		RPOrigins:     []string{"http://localhost:8080"},
	}, func() any { return &identity.Identity{} }, NewMemoryWebAuthnSessionStore())
	if err != nil {
		t.Fatalf("NewWebAuthnStrategy: %v", err)
	}

	// Drive the persistence branch directly. The surrounding ceremony needs a
	// real authenticator response, which is not what this is testing.
	cred := &identity.Credential{
		IdentityID: "user-1",
		Type:       "webauthn",
		Identifier: "cred-2",
	}

	if err := strategy.saveCredential(ctx, ident, cred, WebAuthnHooks{}); err != nil {
		t.Fatalf("saveCredential: %v", err)
	}
	if repo.updates != 1 {
		t.Errorf("UpdateIdentity called %d times, want 1", repo.updates)
	}

	stored, err := repo.GetIdentity(ctx, func() any { return &identity.Identity{} }, "user-1")
	if err != nil {
		t.Fatalf("GetIdentity: %v", err)
	}
	if got := len(stored.(*identity.Identity).Credentials); got != 1 {
		t.Errorf("stored credentials = %d, want 1 — the credential was not persisted", got)
	}
}

// TestWebAuthnUsesTheConfiguredClock proves ceremony expiry runs off the
// injected clock rather than the wall clock, so a caller can drive a session
// to its exact expiry boundary.
func TestWebAuthnUsesTheConfiguredClock(t *testing.T) {
	ctx := context.Background()
	start := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	clock := &fakeClock{now: start}

	store := NewMemoryWebAuthnSessionStore()
	strategy, err := NewWebAuthnStrategy(nil, WebAuthnConfig{
		RPDisplayName: "Test App",
		RPID:          "localhost",
		RPOrigins:     []string{"http://localhost:8080"},
		SessionTTL:    5 * time.Minute,
		Clock:         clock,
	}, func() any { return &identity.Identity{} }, store)
	if err != nil {
		t.Fatalf("NewWebAuthnStrategy: %v", err)
	}

	// A session that expires on the fake clock's timeline. Real wall-clock time
	// is decades past this, so a strategy still calling time.Now() sees it as
	// long expired.
	expires := start.Add(5 * time.Minute)
	if err := store.SaveSession(ctx, "sess", &WebAuthnSessionData{ExpiresAt: expires}); err != nil {
		t.Fatalf("SaveSession: %v", err)
	}

	ident := &identity.Identity{ID: "user-1"}

	// FinishRegistration checks expiry before it parses anything, so a nil
	// response still reaches the check. The distinguishing outcome is the
	// error: "session expired" means the wall clock won.
	_, err = strategy.FinishRegistration(ctx, ident, "sess", "ada@example.com", "Ada", nil)
	if err != nil && strings.Contains(err.Error(), "session expired") {
		t.Fatalf("a session valid on the fake clock was treated as expired: %v", err)
	}

	// Past the TTL on the fake clock, it must expire.
	clock.now = start.Add(6 * time.Minute)
	if err := store.SaveSession(ctx, "sess2", &WebAuthnSessionData{ExpiresAt: expires}); err != nil {
		t.Fatalf("SaveSession: %v", err)
	}
	_, err = strategy.FinishRegistration(ctx, ident, "sess2", "ada@example.com", "Ada", nil)
	if err == nil || !strings.Contains(err.Error(), "session expired") {
		t.Errorf("error = %v, want session expired after advancing the fake clock", err)
	}
}

// TestWebAuthnSignCountFailureIsReported covers an error that was discarded.
// A failed sign-count write means the stored counter stops advancing, and a
// counter that never advances can never go backwards — so the failure silently
// disabled clone detection for that credential.
func TestWebAuthnSignCountFailureIsReported(t *testing.T) {
	strategy := &WebAuthnStrategy{
		repo:  &failingUpdateRepo{},
		clock: &fakeClock{now: time.Now()},
	}

	credConfig, err := json.Marshal(WebAuthnCredentialData{CredentialID: []byte("c")})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	ident := &identity.Identity{
		ID: "user-1",
		Credentials: []identity.Credential{{
			Type:       "webauthn",
			Identifier: base64.RawURLEncoding.EncodeToString([]byte("c")),
			Config:     identity.JSON(credConfig),
		}},
	}

	err = strategy.updateSignCount(context.Background(), ident, &webauthn.Credential{ID: []byte("c")})
	if err == nil {
		t.Error("a failed sign-count write was reported as success")
	}
}

type failingUpdateRepo struct {
	*mockRepo
}

func (r *failingUpdateRepo) UpdateIdentity(ctx context.Context, ident any) error {
	return errors.New("storage unavailable")
}
