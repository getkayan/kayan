package kayantesting

import (
	"context"
	"testing"
	"time"

	"github.com/getkayan/kayan/core/audit"
	"github.com/getkayan/kayan/core/domain"
)

// TestMemoryStoreSatisfiesContract runs the shipped contract suite against the
// in-memory store. If this fails, the suite and the store disagree — and every
// backend validated against the suite inherits that disagreement.
func TestMemoryStoreSatisfiesContract(t *testing.T) {
	StorageSuite(t, func() domain.Storage { return NewMemoryStore() })
}

func TestResetEmptiesTheStore(t *testing.T) {
	ctx := context.Background()
	store := NewMemoryStore()
	factory := func() any { return &SuiteIdentity{} }

	if err := store.CreateIdentity(ctx, &SuiteIdentity{ID: "u1"}); err != nil {
		t.Fatalf("CreateIdentity: %v", err)
	}
	store.Reset()

	if _, err := store.GetIdentity(ctx, factory, "u1"); err == nil {
		t.Error("identity survived Reset")
	}
}

func TestCreateIdentityRejectsDuplicates(t *testing.T) {
	ctx := context.Background()
	store := NewMemoryStore()

	if err := store.CreateIdentity(ctx, &SuiteIdentity{ID: "u1"}); err != nil {
		t.Fatalf("CreateIdentity: %v", err)
	}
	if err := store.CreateIdentity(ctx, &SuiteIdentity{ID: "u1"}); err == nil {
		t.Error("a duplicate ID was accepted")
	}
}

func TestCreateIdentityRejectsMissingID(t *testing.T) {
	ctx := context.Background()
	store := NewMemoryStore()

	// An empty ID would collide with every other empty-ID identity.
	if err := store.CreateIdentity(ctx, &SuiteIdentity{Email: "a@example.test"}); err == nil {
		t.Error("an identity with no ID was accepted")
	}
	if err := store.CreateIdentity(ctx, nil); err == nil {
		t.Error("a nil identity was accepted")
	}
}

func TestUpdateIdentityRequiresAnExistingRecord(t *testing.T) {
	ctx := context.Background()
	store := NewMemoryStore()

	// Update must not silently create; that would mask a caller bug.
	if err := store.UpdateIdentity(ctx, &SuiteIdentity{ID: "absent"}); err == nil {
		t.Error("UpdateIdentity created a record that did not exist")
	}
}

// TestCredentialKeyCannotBeForged guards the composite key. Building it by
// naive concatenation would let a crafted identifier impersonate another
// method's credential.
func TestCredentialKeyCannotBeForged(t *testing.T) {
	a := credentialKey("user@example.test", "password")
	b := credentialKey("test", "passworduser@example.")

	if a == b {
		t.Fatal("two different identifier/method pairs produced the same key")
	}
}

// TestTokenExpiryUsesTheInjectedClock proves expiry is driven by the store's
// clock, so tests can reach an exact boundary without sleeping.
func TestTokenExpiryUsesTheInjectedClock(t *testing.T) {
	ctx := context.Background()
	start := time.Date(2026, 8, 4, 12, 0, 0, 0, time.UTC)
	clock := NewFakeClock(start)
	store := NewMemoryStore(WithClock(clock))

	expiry := start.Add(time.Hour)
	if err := store.SaveToken(ctx, &domain.AuthToken{
		Token: "tok", IdentityID: "u1", Type: "recovery", ExpiresAt: expiry,
	}); err != nil {
		t.Fatalf("SaveToken: %v", err)
	}

	if _, err := store.GetToken(ctx, "tok"); err != nil {
		t.Fatalf("token rejected at issue time: %v", err)
	}

	clock.Set(expiry.Add(-time.Nanosecond))
	if _, err := store.GetToken(ctx, "tok"); err != nil {
		t.Errorf("token rejected one nanosecond before expiry: %v", err)
	}

	clock.Set(expiry)
	if _, err := store.GetToken(ctx, "tok"); err == nil {
		t.Error("token accepted at exactly the expiry instant")
	}
}

func TestAuditQueryFiltersAndPaginates(t *testing.T) {
	ctx := context.Background()
	store := NewMemoryStore()

	base := time.Date(2026, 8, 4, 12, 0, 0, 0, time.UTC)
	for i := range 5 {
		if err := store.SaveEvent(ctx, &audit.AuditEvent{
			ID:        string(rune('a' + i)),
			Type:      "identity.login.success",
			ActorID:   "u1",
			Status:    "success",
			CreatedAt: base.Add(time.Duration(i) * time.Minute),
		}); err != nil {
			t.Fatalf("SaveEvent: %v", err)
		}
	}
	if err := store.SaveEvent(ctx, &audit.AuditEvent{
		ID: "other", Type: "identity.login.failure", ActorID: "u2",
		Status: "failure", CreatedAt: base,
	}); err != nil {
		t.Fatalf("SaveEvent: %v", err)
	}

	byActor, err := store.Query(ctx, audit.Filter{ActorID: "u1"})
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	if len(byActor) != 5 {
		t.Errorf("ActorID filter returned %d events, want 5", len(byActor))
	}

	byType, err := store.Query(ctx, audit.Filter{Types: []string{"identity.login.failure"}})
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	if len(byType) != 1 {
		t.Errorf("Types filter returned %d events, want 1", len(byType))
	}

	page, err := store.Query(ctx, audit.Filter{ActorID: "u1", Limit: 2})
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	if len(page) != 2 {
		t.Errorf("Limit returned %d events, want 2", len(page))
	}

	// Count reports total matches, not the page size — callers use it to work
	// out how many pages there are.
	count, err := store.Count(ctx, audit.Filter{ActorID: "u1", Limit: 2})
	if err != nil {
		t.Fatalf("Count: %v", err)
	}
	if count != 5 {
		t.Errorf("Count = %d, want 5 (Limit must not affect the total)", count)
	}
}

func TestAuditPurgeRemovesOnlyOlderEvents(t *testing.T) {
	ctx := context.Background()
	store := NewMemoryStore()
	base := time.Date(2026, 8, 4, 12, 0, 0, 0, time.UTC)

	for i, when := range []time.Time{base.Add(-2 * time.Hour), base.Add(-time.Hour), base} {
		if err := store.SaveEvent(ctx, &audit.AuditEvent{
			ID: string(rune('a' + i)), Type: "test", CreatedAt: when,
		}); err != nil {
			t.Fatalf("SaveEvent: %v", err)
		}
	}

	purged, err := store.Purge(ctx, base.Add(-90*time.Minute))
	if err != nil {
		t.Fatalf("Purge: %v", err)
	}
	if purged != 1 {
		t.Errorf("purged %d events, want 1", purged)
	}
	if remaining := len(store.Events()); remaining != 2 {
		t.Errorf("%d events remain, want 2", remaining)
	}
}

func TestFakeClockAdvances(t *testing.T) {
	start := time.Date(2026, 8, 4, 12, 0, 0, 0, time.UTC)
	clock := NewFakeClock(start)

	if got := clock.Now(); !got.Equal(start) {
		t.Errorf("Now() = %v, want %v", got, start)
	}

	clock.Advance(90 * time.Minute)
	if got, want := clock.Now(), start.Add(90*time.Minute); !got.Equal(want) {
		t.Errorf("after Advance, Now() = %v, want %v", got, want)
	}

	// Negative advance models clock skew between hosts.
	clock.Advance(-2 * time.Hour)
	if got, want := clock.Now(), start.Add(-30*time.Minute); !got.Equal(want) {
		t.Errorf("after negative Advance, Now() = %v, want %v", got, want)
	}
}
