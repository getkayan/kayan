package flow

import (
	"context"
	"fmt"

	"github.com/getkayan/kayan/core/audit"
	"github.com/getkayan/kayan/core/identity"
)

type RegistrationManager struct {
	repo       IdentityRepository
	auditStore audit.AuditStore
	strategies map[string]RegistrationStrategy
	preHooks   []Hook
	postHooks  []Hook
	factory    func() any
	schema     identity.Schema
}

func NewRegistrationManager(repo IdentityRepository, factory func() any) *RegistrationManager {
	store, ok := repo.(audit.AuditStore)
	var auditStore audit.AuditStore
	if ok {
		auditStore = store
	}

	return &RegistrationManager{
		repo:       repo,
		auditStore: auditStore,
		strategies: make(map[string]RegistrationStrategy),
		factory:    factory,
	}
}

func (m *RegistrationManager) RegisterStrategy(s RegistrationStrategy) {
	m.strategies[s.ID()] = s
}

func (m *RegistrationManager) SetSchema(s identity.Schema) {
	m.schema = s
}

func (m *RegistrationManager) AddPreHook(h Hook)  { m.preHooks = append(m.preHooks, h) }
func (m *RegistrationManager) AddPostHook(h Hook) { m.postHooks = append(m.postHooks, h) }

func (m *RegistrationManager) Submit(ctx context.Context, method string, traits identity.JSON, secret string) (any, error) {
	strategy, ok := m.strategies[method]
	if !ok {
		return nil, fmt.Errorf("registration: unknown method %q", method)
	}

	// 1. Pre-hooks
	for _, h := range m.preHooks {
		if err := h(ctx, nil); err != nil {
			return nil, err
		}
	}

	// 2. Schema Validation
	if m.schema != nil {
		if err := m.schema.Validate(traits); err != nil {
			return nil, fmt.Errorf("registration: validation failed: %v", err)
		}
	}

	// 3. Delegate to strategy
	ident, err := strategy.Register(ctx, traits, secret)
	if err != nil {
		if m.auditStore != nil {
			m.auditStore.SaveEvent(ctx, &audit.AuditEvent{
				Type:    "identity.registration.failure",
				Status:  "failure",
				Message: err.Error(),
			})
		}
		return nil, err
	}

	if m.auditStore != nil {
		m.auditStore.SaveEvent(ctx, &audit.AuditEvent{
			Type:   "identity.registration.success",
			Status: "success",
		})
	}

	// 3. Post-hooks
	for _, h := range m.postHooks {
		if err := h(ctx, ident); err != nil {
			return nil, err
		}
	}

	return ident, nil
}
