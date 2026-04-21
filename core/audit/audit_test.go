package audit

import (
	"context"
	"strings"
	"testing"
	"time"
)

type memStore struct {
	events []*AuditEvent
}

func (m *memStore) SaveEvent(_ context.Context, event *AuditEvent) error {
	m.events = append(m.events, event)
	return nil
}
func (m *memStore) Query(_ context.Context, filter Filter) ([]AuditEvent, error) {
	var out []AuditEvent
	for _, e := range m.events {
		if filter.ActorID != "" && e.ActorID != filter.ActorID {
			continue
		}
		if len(filter.Types) > 0 && !contains(filter.Types, e.Type) {
			continue
		}
		out = append(out, *e)
	}
	return out, nil
}
func (m *memStore) Count(_ context.Context, filter Filter) (int64, error) {
	evs, _ := m.Query(context.Background(), filter)
	return int64(len(evs)), nil
}
func (m *memStore) Export(_ context.Context, filter Filter, format ExportFormat) (interface{ Read([]byte) (int, error) }, error) {
	return strings.NewReader("export"), nil
}
func (m *memStore) Purge(_ context.Context, olderThan time.Time) (int64, error) {
	before := len(m.events)
	var keep []*AuditEvent
	for _, e := range m.events {
		if e.CreatedAt.After(olderThan) {
			keep = append(keep, e)
		}
	}
	m.events = keep
	return int64(before - len(keep)), nil
}
func contains(list []string, v string) bool {
	for _, s := range list {
		if s == v {
			return true
		}
	}
	return false
}

func TestEventBuilderAndMemStore(t *testing.T) {
	store := &memStore{}
	event := NewEvent(EventLoginSuccess).
		ID("id-1").
		Actor("actor-1").
		Subject("subject-1").
		Success().
		Message("ok").
		Build()
	// Make event old enough to be purged
	event.CreatedAt = time.Now().Add(-2 * time.Hour)
	if event.Type != EventLoginSuccess || event.Status != "success" || event.ActorID != "actor-1" {
		t.Fatalf("unexpected event: %+v", event)
	}
	if err := store.SaveEvent(context.Background(), event); err != nil {
		t.Fatalf("save event: %v", err)
	}
	results, err := store.Query(context.Background(), Filter{ActorID: "actor-1"})
	if err != nil || len(results) != 1 {
		t.Fatalf("query: %v, results: %d", err, len(results))
	}
	count, err := store.Count(context.Background(), Filter{ActorID: "actor-1"})
	if err != nil || count != 1 {
		t.Fatalf("count: %v, got %d", err, count)
	}
	purged, err := store.Purge(context.Background(), time.Now())
	if err != nil || purged != 1 {
		t.Fatalf("purge: %v, got %d", err, purged)
	}
}
