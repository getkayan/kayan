package flow

import (
	"context"
	"io"
	"sync"
	"testing"
	"time"

	"github.com/getkayan/kayan/core/audit"
	"github.com/getkayan/kayan/core/identity"
)

type quickAuditStore struct {
	mu     sync.Mutex
	events []audit.AuditEvent
}

func (s *quickAuditStore) SaveEvent(_ context.Context, event *audit.AuditEvent) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.events = append(s.events, *event)
	return nil
}
func (*quickAuditStore) Query(context.Context, audit.Filter) ([]audit.AuditEvent, error) {
	return nil, nil
}
func (*quickAuditStore) Count(context.Context, audit.Filter) (int64, error) { return 0, nil }
func (*quickAuditStore) Export(context.Context, audit.Filter, audit.ExportFormat) (io.Reader, error) {
	return nil, nil
}
func (*quickAuditStore) Purge(context.Context, time.Time) (int64, error) { return 0, nil }

func (s *quickAuditStore) snapshot() []audit.AuditEvent {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]audit.AuditEvent(nil), s.events...)
}

func TestPasswordAuthPersistsRegistrationAndLoginAudit(t *testing.T) {
	repo := &mockRepo{identities: map[string]any{}, creds: map[string]*identity.Credential{}}
	sink := &quickAuditStore{}
	reg, login := PasswordAuth(
		repo, func() any { return &identity.Identity{} }, "email",
		WithHasherCost(4), WithQuickAudit(sink, func(context.Context, error) {}),
	)
	ctx := context.Background()
	if _, err := reg.Submit(ctx, "password", identity.JSON(`{"email":"audited@example.test"}`), "correct horse battery staple"); err != nil {
		t.Fatalf("register: %v", err)
	}
	if _, err := login.Authenticate(ctx, "password", "audited@example.test", "correct horse battery staple"); err != nil {
		t.Fatalf("login: %v", err)
	}

	events := sink.snapshot()
	if len(events) != 2 {
		t.Fatalf("audit event count = %d, want 2: %#v", len(events), events)
	}
	if events[0].Type != audit.EventUserCreated || events[1].Type != audit.EventLoginSuccess {
		t.Fatalf("audit types = %q, %q", events[0].Type, events[1].Type)
	}
}
