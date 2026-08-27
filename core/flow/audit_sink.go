package flow

import (
	"context"

	"github.com/getkayan/kayan/core/audit"
)

// AuditErrorHandler receives persistence failures from an explicitly configured
// audit store. Authentication side effects are not rolled back after an audit
// write fails, so callers must route these errors to durable alerting.
type AuditErrorHandler func(ctx context.Context, err error)

type auditSink struct {
	store   audit.AuditStore
	onError AuditErrorHandler
}

func newAuditSink(store audit.AuditStore, onError AuditErrorHandler) *auditSink {
	if store == nil {
		return nil
	}
	if onError == nil {
		panic("flow: audit error handler is required with an audit store")
	}
	return &auditSink{store: store, onError: onError}
}

func (s *auditSink) save(ctx context.Context, event *audit.AuditEvent) {
	if s == nil {
		return
	}
	if err := s.store.SaveEvent(ctx, event); err != nil {
		s.onError(ctx, err)
	}
}
