package flow

import (
	"context"
	"errors"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/getkayan/kayan/core/audit"
)

type failingAuditStore struct{ err error }

func (s failingAuditStore) SaveEvent(context.Context, *audit.AuditEvent) error { return s.err }
func (failingAuditStore) Query(context.Context, audit.Filter) ([]audit.AuditEvent, error) {
	return nil, nil
}
func (failingAuditStore) Count(context.Context, audit.Filter) (int64, error) { return 0, nil }
func (failingAuditStore) Export(context.Context, audit.Filter, audit.ExportFormat) (io.Reader, error) {
	return strings.NewReader(""), nil
}
func (failingAuditStore) Purge(context.Context, time.Time) (int64, error) { return 0, nil }

func TestAuditSinkReportsPersistenceFailure(t *testing.T) {
	want := errors.New("audit unavailable")
	var got error
	sink := newAuditSink(failingAuditStore{err: want}, func(_ context.Context, err error) { got = err })
	sink.save(context.Background(), &audit.AuditEvent{Type: "test"})
	if !errors.Is(got, want) {
		t.Fatalf("reported error = %v, want %v", got, want)
	}
}

func TestAuditSinkRequiresErrorHandler(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Fatal("expected panic for audit store without error handler")
		}
	}()
	newAuditSink(failingAuditStore{}, nil)
}
