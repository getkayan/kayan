package policy

import (
	"context"
	"io"
	"sync/atomic"
	"testing"
	"time"

	"github.com/getkayan/kayan/core/audit"
)

// Mock Audit Store
type mockAudit struct {
	events []*audit.AuditEvent
}

func (m *mockAudit) SaveEvent(ctx context.Context, e *audit.AuditEvent) error {
	m.events = append(m.events, e)
	return nil
}

func (m *mockAudit) Count(ctx context.Context, filter audit.Filter) (int64, error) {
	return 0, nil
}

func (m *mockAudit) Query(ctx context.Context, filter audit.Filter) ([]audit.AuditEvent, error) {
	return nil, nil
}

func (m *mockAudit) Export(ctx context.Context, filter audit.Filter, format audit.ExportFormat) (io.Reader, error) {
	return nil, nil
}

func (m *mockAudit) Purge(ctx context.Context, olderThan time.Time) (int64, error) {
	return 0, nil
}

// Mock Engine to count calls
type mockCounterEngine struct {
	calls int32
}

func (m *mockCounterEngine) Can(ctx context.Context, sub any, act string, res any) (bool, error) {
	atomic.AddInt32(&m.calls, 1)
	return true, nil
}

func TestAuditMiddleware(t *testing.T) {
	mockStore := &mockAudit{}
	core := &mockCounterEngine{}

	// Wrap core with Audit
	engine := NewAuditMiddleware(core, mockStore)

	// Call Can
	engine.Can(context.Background(), "user1", "read", "doc1")

	// Verify Audit Log (Async, so sleep briefly)
	time.Sleep(10 * time.Millisecond)

	if len(mockStore.events) != 1 {
		t.Fatalf("Expected 1 audit event, got %d", len(mockStore.events))
	}

	evt := mockStore.events[0]
	if evt.ActorID != "user1" || evt.Type != "policy.decision" {
		t.Errorf("Audit event mismatch: %+v", evt)
	}
	// Action is now in Metadata or implicit in Message
}

func TestCachingMiddleware(t *testing.T) {
	core := &mockCounterEngine{}

	// Wrap with Cache (100ms TTL)
	engine := NewCachingMiddleware(core, 100*time.Millisecond)

	// 1. First Call - Count should increase
	engine.Can(context.Background(), "user1", "read", "doc1")
	if atomic.LoadInt32(&core.calls) != 1 {
		t.Errorf("Expected 1 call, got %d", core.calls)
	}

	// 2. Second Call (Immediate) - Should hit cache, Count STAYS 1
	engine.Can(context.Background(), "user1", "read", "doc1")
	if atomic.LoadInt32(&core.calls) != 1 {
		t.Errorf("Expected cache hit (calls=1), got %d", core.calls)
	}

	// 3. Different Inputs - Should miss cache, Count increases to 2
	engine.Can(context.Background(), "user2", "read", "doc1")
	if atomic.LoadInt32(&core.calls) != 2 {
		t.Errorf("Expected 2 calls, got %d", core.calls)
	}

	// 4. Wait for Expiry
	time.Sleep(150 * time.Millisecond)

	// 5. Expired Call - Should miss cache, Count increases to 3
	engine.Can(context.Background(), "user1", "read", "doc1")
	if atomic.LoadInt32(&core.calls) != 3 {
		t.Errorf("Expected 3 calls (expiry), got %d", core.calls)
	}
}
