package audit

import (
	"context"
	"errors"
	"io"
	"testing"
	"time"

	"github.com/getkayan/kayan/core/identity"
)

// The audit trail is a compliance control and the record an incident is
// reconstructed from. If Logger drops an event, nothing else in the system
// notices -- there is no second copy to disagree with, and the library writes
// no logs of its own. That makes the failure paths here worth more than the
// happy one.

// countingStore records what it was asked to persist and can be told to fail.
type countingStore struct {
	saved []AuditEvent
	err   error
}

func (s *countingStore) SaveEvent(_ context.Context, event *AuditEvent) error {
	if s.err != nil {
		return s.err
	}
	s.saved = append(s.saved, *event)
	return nil
}

func (s *countingStore) Query(context.Context, Filter) ([]AuditEvent, error) {
	return s.saved, nil
}
func (s *countingStore) Count(context.Context, Filter) (int64, error) {
	return int64(len(s.saved)), nil
}
func (s *countingStore) Export(context.Context, Filter, ExportFormat) (io.Reader, error) {
	return nil, nil
}
func (s *countingStore) Purge(context.Context, time.Time) (int64, error) { return 0, nil }

// TestLogReportsAStoreFailure covers the case that matters most: the sink is
// broken. A dropped audit event is invisible -- there is nothing to compare
// against and no log line to notice -- so the error must reach the caller,
// which is the only party that can decide whether to fail the operation.
func TestLogReportsAStoreFailure(t *testing.T) {
	storeErr := errors.New("audit table unavailable")
	store := &countingStore{err: storeErr}
	logger := NewLogger(store, Hooks{})

	err := logger.Log(context.Background(), &AuditEvent{Type: "login.success"})
	if !errors.Is(err, storeErr) {
		t.Errorf("error = %v, want the store failure", err)
	}
}

// TestBeforeSaveCanPreventPersistence pins the documented contract: the hook
// may refuse an event, and refusing means it is not written.
func TestBeforeSaveCanPreventPersistence(t *testing.T) {
	store := &countingStore{}
	refuse := errors.New("refused by policy")
	logger := NewLogger(store, Hooks{
		BeforeSave: func(context.Context, *AuditEvent) error { return refuse },
	})

	err := logger.Log(context.Background(), &AuditEvent{Type: "login.success"})
	if !errors.Is(err, refuse) {
		t.Errorf("error = %v, want the hook's refusal", err)
	}
	if len(store.saved) != 0 {
		t.Errorf("the event was persisted despite BeforeSave refusing it")
	}
}

// TestEnrichmentFailureStopsTheWrite covers ordering. Enrichment runs first,
// so a failure there must prevent the write rather than persisting a
// half-populated event that later looks like the complete record.
func TestEnrichmentFailureStopsTheWrite(t *testing.T) {
	store := &countingStore{}
	enrichErr := errors.New("geo lookup failed")
	var beforeSaveRan bool
	logger := NewLogger(store, Hooks{
		EnrichEvent: func(context.Context, *AuditEvent) error { return enrichErr },
		BeforeSave: func(context.Context, *AuditEvent) error {
			beforeSaveRan = true
			return nil
		},
	})

	if err := logger.Log(context.Background(), &AuditEvent{Type: "login.success"}); !errors.Is(err, enrichErr) {
		t.Errorf("error = %v, want the enrichment failure", err)
	}
	if len(store.saved) != 0 {
		t.Error("an event was persisted after enrichment failed")
	}
	if beforeSaveRan {
		t.Error("BeforeSave ran after enrichment had already failed")
	}
}

// TestEnrichmentReachesTheStore is the positive half: what a hook adds must be
// what gets written, not a copy taken beforehand.
func TestEnrichmentReachesTheStore(t *testing.T) {
	store := &countingStore{}
	logger := NewLogger(store, Hooks{
		EnrichEvent: func(_ context.Context, e *AuditEvent) error {
			e.IPAddress = "198.51.100.7"
			return nil
		},
		IDGenerator: func() string { return "generated-id" },
	})

	if err := logger.Log(context.Background(), &AuditEvent{Type: "login.success"}); err != nil {
		t.Fatalf("Log: %v", err)
	}
	if len(store.saved) != 1 {
		t.Fatalf("persisted %d events, want 1", len(store.saved))
	}
	if store.saved[0].IPAddress != "198.51.100.7" {
		t.Error("the enriched field did not reach the store")
	}
	if store.saved[0].ID != "generated-id" {
		t.Errorf("ID = %q, want the generated one", store.saved[0].ID)
	}
}

// TestExistingIDIsNotOverwritten keeps the generator from replacing an ID the
// caller set deliberately, which would break correlation with whatever issued
// it.
func TestExistingIDIsNotOverwritten(t *testing.T) {
	store := &countingStore{}
	logger := NewLogger(store, Hooks{
		IDGenerator: func() string { return "generated-id" },
	})

	if err := logger.Log(context.Background(), &AuditEvent{ID: "caller-id", Type: "x"}); err != nil {
		t.Fatalf("Log: %v", err)
	}
	if store.saved[0].ID != "caller-id" {
		t.Errorf("ID = %q, want the caller's own", store.saved[0].ID)
	}
}

// TestAfterSaveRunsOnlyAfterAWrite keeps a post-persistence hook -- which is
// where a deployment fans events out to a SIEM -- from firing for an event
// that was never stored.
func TestAfterSaveRunsOnlyAfterAWrite(t *testing.T) {
	var ran bool
	hooks := Hooks{AfterSave: func(context.Context, *AuditEvent) { ran = true }}

	failing := NewLogger(&countingStore{err: errors.New("down")}, hooks)
	_ = failing.Log(context.Background(), &AuditEvent{Type: "x"})
	if ran {
		t.Error("AfterSave ran although the event was never persisted")
	}

	ran = false
	working := NewLogger(&countingStore{}, hooks)
	if err := working.Log(context.Background(), &AuditEvent{Type: "x"}); err != nil {
		t.Fatalf("Log: %v", err)
	}
	if !ran {
		t.Error("AfterSave did not run for a persisted event")
	}
}

// TestAlertOnRiskFiresForHighAndCritical pins which levels alert. Getting this
// wrong is silent in both directions: too narrow and a critical event pages
// nobody, too wide and the alert becomes noise people mute.
func TestAlertOnRiskFiresForHighAndCritical(t *testing.T) {
	cases := []struct {
		risk RiskLevel
		want bool
	}{
		{RiskCritical, true},
		{RiskHigh, true},
		{RiskMedium, false},
		{RiskLow, false},
		{"", false},
	}
	for _, tc := range cases {
		t.Run(string(tc.risk), func(t *testing.T) {
			var alerted bool
			logger := NewLogger(&countingStore{}, Hooks{
				AlertOnRisk: func(context.Context, *AuditEvent) { alerted = true },
			})
			if err := logger.Log(context.Background(), &AuditEvent{Type: "x", Risk: tc.risk}); err != nil {
				t.Fatalf("Log: %v", err)
			}
			if alerted != tc.want {
				t.Errorf("alerted = %v for risk %q, want %v", alerted, tc.risk, tc.want)
			}
		})
	}
}

// TestAlertDoesNotFireForAnUnwrittenEvent keeps the alert honest about what it
// is reporting: an event that failed to persist has not happened as far as the
// trail is concerned.
func TestAlertDoesNotFireForAnUnwrittenEvent(t *testing.T) {
	var alerted bool
	logger := NewLogger(&countingStore{err: errors.New("down")}, Hooks{
		AlertOnRisk: func(context.Context, *AuditEvent) { alerted = true },
	})

	_ = logger.Log(context.Background(), &AuditEvent{Type: "x", Risk: RiskCritical})
	if alerted {
		t.Error("a critical alert fired for an event that was never stored")
	}
}

// TestBuilderSavesWhatItBuilt covers the fluent path end to end, including
// that the builder does not lose fields on the way to the store.
func TestBuilderSavesWhatItBuilt(t *testing.T) {
	store := &countingStore{}
	err := NewEvent("login.failure").
		Actor("alice").
		Subject("resource-1").
		Failure().
		Tenant("tenant-a").
		IP("203.0.113.9").
		Risk(RiskHigh).
		Metadata(identity.JSON(`{"strategy":"password"}`)).
		Save(context.Background(), store)
	if err != nil {
		t.Fatalf("Save: %v", err)
	}

	if len(store.saved) != 1 {
		t.Fatalf("persisted %d events, want 1", len(store.saved))
	}
	got := store.saved[0]
	if got.Type != "login.failure" || got.ActorID != "alice" || got.SubjectID != "resource-1" {
		t.Errorf("event identity fields did not survive the builder: %+v", got)
	}
	if got.Status != "failure" {
		t.Errorf("Status = %q, want failure", got.Status)
	}
	if got.TenantID != "tenant-a" || got.IPAddress != "203.0.113.9" || got.Risk != RiskHigh {
		t.Errorf("context fields did not survive the builder: %+v", got)
	}
}

// TestBuilderReportsASaveFailure keeps the convenience path as loud as the
// Logger path. A fluent chain that swallows its error is the easiest way to
// lose an audit record.
func TestBuilderReportsASaveFailure(t *testing.T) {
	storeErr := errors.New("audit table unavailable")
	err := NewEvent("login.failure").Actor("alice").
		Save(context.Background(), &countingStore{err: storeErr})
	if !errors.Is(err, storeErr) {
		t.Errorf("error = %v, want the store failure", err)
	}
}
