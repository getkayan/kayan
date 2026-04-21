package consent

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"
)

// ---- In-Memory Store ----

type memoryStore struct {
	mu       sync.RWMutex
	consents map[string][]*Consent // keyed by identityID
}

func newMemoryStore() *memoryStore {
	return &memoryStore{consents: make(map[string][]*Consent)}
}

func (s *memoryStore) Save(_ context.Context, c *Consent) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	list := s.consents[c.IdentityID]
	for i, existing := range list {
		if existing.Purpose == c.Purpose {
			list[i] = c
			return nil
		}
	}
	s.consents[c.IdentityID] = append(list, c)
	return nil
}

func (s *memoryStore) Get(_ context.Context, identityID string, purpose Purpose) (*Consent, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, c := range s.consents[identityID] {
		if c.Purpose == purpose {
			return c, nil
		}
	}
	return nil, ErrConsentNotFound
}

func (s *memoryStore) GetAll(_ context.Context, identityID string) ([]*Consent, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	result := make([]*Consent, len(s.consents[identityID]))
	copy(result, s.consents[identityID])
	return result, nil
}

func (s *memoryStore) GetHistory(_ context.Context, identityID string, purpose Purpose) ([]*Consent, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var result []*Consent
	for _, c := range s.consents[identityID] {
		if c.Purpose == purpose {
			result = append(result, c)
		}
	}
	return result, nil
}

func (s *memoryStore) Delete(_ context.Context, identityID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.consents, identityID)
	return nil
}

func (s *memoryStore) FindExpired(_ context.Context, before time.Time) ([]*Consent, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var result []*Consent
	for _, list := range s.consents {
		for _, c := range list {
			if !c.ExpiresAt.IsZero() && c.ExpiresAt.Before(before) && c.Granted {
				result = append(result, c)
			}
		}
	}
	return result, nil
}

// ---- Manager Tests ----

func TestManager_Grant(t *testing.T) {
	store := newMemoryStore()
	mgr := NewManager(store, "v1.0")

	consent, err := mgr.Grant(context.Background(), &ConsentRequest{
		IdentityID: "user-1",
		Purpose:    PurposeMarketing,
		Granted:    true,
		Source:     "registration",
	})
	if err != nil {
		t.Fatalf("Grant failed: %v", err)
	}
	if consent.Purpose != PurposeMarketing {
		t.Errorf("expected purpose %s, got %s", PurposeMarketing, consent.Purpose)
	}
	if consent.Version != "v1.0" {
		t.Errorf("expected version v1.0, got %s", consent.Version)
	}
	if !consent.Granted {
		t.Error("expected granted to be true")
	}
	if consent.GrantedAt.IsZero() {
		t.Error("expected GrantedAt to be set")
	}
}

func TestManager_GrantWithExpiry(t *testing.T) {
	store := newMemoryStore()
	mgr := NewManager(store, "v1.0")

	consent, err := mgr.Grant(context.Background(), &ConsentRequest{
		IdentityID: "user-1",
		Purpose:    PurposeAnalytics,
		Granted:    true,
		Source:     "settings",
		ExpiresIn:  24 * time.Hour,
	})
	if err != nil {
		t.Fatalf("Grant failed: %v", err)
	}
	if consent.ExpiresAt.IsZero() {
		t.Error("expected ExpiresAt to be set")
	}
	if consent.ExpiresAt.Before(time.Now()) {
		t.Error("expected ExpiresAt to be in the future")
	}
}

func TestManager_Check(t *testing.T) {
	store := newMemoryStore()
	mgr := NewManager(store, "v1.0")
	ctx := context.Background()

	// Not granted yet
	granted, err := mgr.Check(ctx, "user-1", PurposeMarketing)
	if err != nil {
		t.Fatalf("Check failed: %v", err)
	}
	if granted {
		t.Error("expected not granted before granting")
	}

	// Grant
	_, _ = mgr.Grant(ctx, &ConsentRequest{
		IdentityID: "user-1",
		Purpose:    PurposeMarketing,
		Granted:    true,
		Source:     "test",
	})

	// Now should be granted
	granted, err = mgr.Check(ctx, "user-1", PurposeMarketing)
	if err != nil {
		t.Fatalf("Check failed: %v", err)
	}
	if !granted {
		t.Error("expected granted after granting")
	}
}

func TestManager_CheckExpired(t *testing.T) {
	store := newMemoryStore()
	mgr := NewManager(store, "v1.0")
	ctx := context.Background()

	// Grant with past expiry (simulate expired consent)
	store.Save(ctx, &Consent{
		IdentityID: "user-1",
		Purpose:    PurposeAnalytics,
		Granted:    true,
		ExpiresAt:  time.Now().Add(-1 * time.Hour),
	})

	granted, _ := mgr.Check(ctx, "user-1", PurposeAnalytics)
	if granted {
		t.Error("expected expired consent to not be granted")
	}
}

func TestManager_CheckEssentialAlwaysGranted(t *testing.T) {
	store := newMemoryStore()
	mgr := NewManager(store, "v1.0", WithEssentialPurposes(PurposeEssential))

	// Essential should be granted even without explicit consent record
	granted, err := mgr.Check(context.Background(), "user-1", PurposeEssential)
	if err != nil {
		t.Fatalf("Check failed: %v", err)
	}
	if !granted {
		t.Error("expected essential purpose to always be granted")
	}
}

func TestManager_Revoke(t *testing.T) {
	store := newMemoryStore()
	mgr := NewManager(store, "v1.0")
	ctx := context.Background()

	// Grant then revoke
	_, _ = mgr.Grant(ctx, &ConsentRequest{
		IdentityID: "user-1",
		Purpose:    PurposeMarketing,
		Granted:    true,
		Source:     "test",
	})

	err := mgr.Revoke(ctx, "user-1", PurposeMarketing)
	if err != nil {
		t.Fatalf("Revoke failed: %v", err)
	}

	granted, _ := mgr.Check(ctx, "user-1", PurposeMarketing)
	if granted {
		t.Error("expected not granted after revocation")
	}
}

func TestManager_RevokeEssentialFails(t *testing.T) {
	store := newMemoryStore()
	mgr := NewManager(store, "v1.0", WithEssentialPurposes(PurposeEssential))
	ctx := context.Background()

	// Grant essential
	_, _ = mgr.Grant(ctx, &ConsentRequest{
		IdentityID: "user-1",
		Purpose:    PurposeEssential,
		Granted:    true,
		Source:     "test",
	})

	// Revoking essential should fail
	err := mgr.Revoke(ctx, "user-1", PurposeEssential)
	if err != ErrEssentialConsent {
		t.Errorf("expected ErrEssentialConsent, got %v", err)
	}
}

func TestManager_GetAll(t *testing.T) {
	store := newMemoryStore()
	mgr := NewManager(store, "v1.0")
	ctx := context.Background()

	_, _ = mgr.Grant(ctx, &ConsentRequest{IdentityID: "user-1", Purpose: PurposeMarketing, Granted: true, Source: "test"})
	_, _ = mgr.Grant(ctx, &ConsentRequest{IdentityID: "user-1", Purpose: PurposeAnalytics, Granted: true, Source: "test"})

	all, err := mgr.GetAll(ctx, "user-1")
	if err != nil {
		t.Fatalf("GetAll failed: %v", err)
	}
	if len(all) != 2 {
		t.Errorf("expected 2 consents, got %d", len(all))
	}
}

func TestManager_DeleteAll(t *testing.T) {
	store := newMemoryStore()
	mgr := NewManager(store, "v1.0")
	ctx := context.Background()

	_, _ = mgr.Grant(ctx, &ConsentRequest{IdentityID: "user-1", Purpose: PurposeMarketing, Granted: true, Source: "test"})
	_, _ = mgr.Grant(ctx, &ConsentRequest{IdentityID: "user-1", Purpose: PurposeAnalytics, Granted: true, Source: "test"})

	err := mgr.DeleteAll(ctx, "user-1")
	if err != nil {
		t.Fatalf("DeleteAll failed: %v", err)
	}

	all, _ := mgr.GetAll(ctx, "user-1")
	if len(all) != 0 {
		t.Errorf("expected 0 consents after delete, got %d", len(all))
	}
}

func TestManager_ExportConsents(t *testing.T) {
	store := newMemoryStore()
	mgr := NewManager(store, "v1.0")
	ctx := context.Background()

	_, _ = mgr.Grant(ctx, &ConsentRequest{IdentityID: "user-1", Purpose: PurposeMarketing, Granted: true, Source: "test"})

	export, err := mgr.ExportConsents(ctx, "user-1")
	if err != nil {
		t.Fatalf("ExportConsents failed: %v", err)
	}
	if export.IdentityID != "user-1" {
		t.Errorf("expected identity user-1, got %s", export.IdentityID)
	}
	if len(export.Consents) != 1 {
		t.Errorf("expected 1 consent in export, got %d", len(export.Consents))
	}
	if export.Format != "json" {
		t.Errorf("expected format json, got %s", export.Format)
	}
}

func TestManager_ProcessExpired(t *testing.T) {
	store := newMemoryStore()
	var expiredCalled int
	mgr := NewManager(store, "v1.0", WithHooks(Hooks{
		OnExpired: func(_ context.Context, _ *Consent) {
			expiredCalled++
		},
	}))
	ctx := context.Background()

	// Insert an already-expired consent directly
	store.Save(ctx, &Consent{
		IdentityID: "user-1",
		Purpose:    PurposeMarketing,
		Granted:    true,
		ExpiresAt:  time.Now().Add(-1 * time.Hour),
	})

	err := mgr.ProcessExpired(ctx)
	if err != nil {
		t.Fatalf("ProcessExpired failed: %v", err)
	}
	if expiredCalled != 1 {
		t.Errorf("expected OnExpired called 1 time, got %d", expiredCalled)
	}
}

func TestManager_Hooks(t *testing.T) {
	store := newMemoryStore()
	var beforeGrantCalled, afterGrantCalled, beforeRevokeCalled, afterRevokeCalled bool

	mgr := NewManager(store, "v1.0", WithHooks(Hooks{
		BeforeGrant:  func(_ context.Context, _ *ConsentRequest) error { beforeGrantCalled = true; return nil },
		AfterGrant:   func(_ context.Context, _ *Consent) { afterGrantCalled = true },
		BeforeRevoke: func(_ context.Context, _ *Consent) error { beforeRevokeCalled = true; return nil },
		AfterRevoke:  func(_ context.Context, _ *Consent) { afterRevokeCalled = true },
	}))
	ctx := context.Background()

	_, _ = mgr.Grant(ctx, &ConsentRequest{IdentityID: "user-1", Purpose: PurposeMarketing, Granted: true, Source: "test"})
	if !beforeGrantCalled {
		t.Error("expected BeforeGrant hook to be called")
	}
	if !afterGrantCalled {
		t.Error("expected AfterGrant hook to be called")
	}

	_ = mgr.Revoke(ctx, "user-1", PurposeMarketing)
	if !beforeRevokeCalled {
		t.Error("expected BeforeRevoke hook to be called")
	}
	if !afterRevokeCalled {
		t.Error("expected AfterRevoke hook to be called")
	}
}

func TestManager_BeforeGrantHookRejectsGrant(t *testing.T) {
	store := newMemoryStore()
	mgr := NewManager(store, "v1.0", WithHooks(Hooks{
		BeforeGrant: func(_ context.Context, _ *ConsentRequest) error {
			return errors.New("rejected")
		},
	}))

	_, err := mgr.Grant(context.Background(), &ConsentRequest{
		IdentityID: "user-1",
		Purpose:    PurposeMarketing,
		Granted:    true,
		Source:     "test",
	})
	if err == nil {
		t.Error("expected grant to be rejected by hook")
	}
}

func TestManager_ValidatePurposeHook(t *testing.T) {
	store := newMemoryStore()
	mgr := NewManager(store, "v1.0", WithHooks(Hooks{
		ValidatePurpose: func(_ context.Context, p Purpose) error {
			if p == "evil_purpose" {
				return fmt.Errorf("invalid purpose: %s", p)
			}
			return nil
		},
	}))

	_, err := mgr.Grant(context.Background(), &ConsentRequest{
		IdentityID: "user-1",
		Purpose:    "evil_purpose",
		Granted:    true,
		Source:     "test",
	})
	if err == nil {
		t.Error("expected invalid purpose to be rejected")
	}
}

func TestManager_IDGeneratorHook(t *testing.T) {
	store := newMemoryStore()
	mgr := NewManager(store, "v1.0", WithHooks(Hooks{
		IDGenerator: func() string { return "custom-id-123" },
	}))

	consent, err := mgr.Grant(context.Background(), &ConsentRequest{
		IdentityID: "user-1",
		Purpose:    PurposeMarketing,
		Granted:    true,
		Source:     "test",
	})
	if err != nil {
		t.Fatalf("Grant failed: %v", err)
	}
	if consent.ID != "custom-id-123" {
		t.Errorf("expected custom ID, got %s", consent.ID)
	}
}

func TestManager_UpdateVersion(t *testing.T) {
	store := newMemoryStore()
	mgr := NewManager(store, "v1.0")
	ctx := context.Background()

	c1, _ := mgr.Grant(ctx, &ConsentRequest{IdentityID: "user-1", Purpose: PurposeMarketing, Granted: true, Source: "test"})
	if c1.Version != "v1.0" {
		t.Errorf("expected v1.0, got %s", c1.Version)
	}

	mgr.UpdateVersion("v2.0")

	c2, _ := mgr.Grant(ctx, &ConsentRequest{IdentityID: "user-2", Purpose: PurposeMarketing, Granted: true, Source: "test"})
	if c2.Version != "v2.0" {
		t.Errorf("expected v2.0, got %s", c2.Version)
	}
}

// ---- Context Helper Tests ----

func TestContextHelpers(t *testing.T) {
	ctx := context.Background()

	// No consents in context
	if HasConsent(ctx, PurposeMarketing) {
		t.Error("expected no consent in empty context")
	}

	consents := map[Purpose]bool{
		PurposeMarketing: true,
		PurposeAnalytics: false,
	}
	ctx = WithConsents(ctx, consents)

	if !HasConsent(ctx, PurposeMarketing) {
		t.Error("expected marketing consent in context")
	}
	if HasConsent(ctx, PurposeAnalytics) {
		t.Error("expected analytics consent to be false")
	}
	if HasConsent(ctx, PurposeThirdParty) {
		t.Error("expected third_party consent to be false (missing)")
	}

	fromCtx := ConsentsFromContext(ctx)
	if fromCtx == nil {
		t.Error("expected consents from context")
	}
	if len(fromCtx) != 2 {
		t.Errorf("expected 2 consents, got %d", len(fromCtx))
	}
}

// ---- RequireConsentFunc Test ----

func TestRequireConsentFunc(t *testing.T) {
	store := newMemoryStore()
	mgr := NewManager(store, "v1.0")
	ctx := context.Background()

	fn := func(_ context.Context, identityID string) (any, error) {
		return "result-" + identityID, nil
	}

	wrapped := RequireConsentFunc(mgr, PurposeMarketing, fn)

	// No consent → should fail
	_, err := wrapped(ctx, "user-1")
	if err == nil {
		t.Error("expected error when consent not granted")
	}

	// Grant consent → should succeed
	_, _ = mgr.Grant(ctx, &ConsentRequest{IdentityID: "user-1", Purpose: PurposeMarketing, Granted: true, Source: "test"})

	result, err := wrapped(ctx, "user-1")
	if err != nil {
		t.Fatalf("expected no error after grant, got: %v", err)
	}
	if result != "result-user-1" {
		t.Errorf("expected result-user-1, got %v", result)
	}
}

// ---- Middleware Tests ----

func TestRequireConsentMiddleware(t *testing.T) {
	store := newMemoryStore()
	mgr := NewManager(store, "v1.0")
	ctx := context.Background()

	// Grant consent
	_, _ = mgr.Grant(ctx, &ConsentRequest{IdentityID: "user-1", Purpose: PurposeMarketing, Granted: true, Source: "test"})

	cfg := MiddlewareConfig{
		Manager: mgr,
		IdentityExtractor: func(ctx context.Context) (string, error) {
			return "user-1", nil
		},
		Purpose: PurposeMarketing,
	}

	handler := RequireConsent(cfg)
	if handler == nil {
		t.Fatal("expected non-nil middleware")
	}
}
