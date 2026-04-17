package flow

import (
	"context"
	"fmt"

	"github.com/getkayan/kayan/core/audit"
	"github.com/getkayan/kayan/core/events"
	"github.com/getkayan/kayan/core/identity"
)

type RegistrationManager struct {
	repo       IdentityRepository
	auditStore audit.AuditStore
	dispatcher events.Dispatcher
	strategies map[string]RegistrationStrategy
	preHooks   []Hook
	postHooks  []Hook
	factory    func() any
	schema     identity.Schema
	linker                 Linker
	PreventPasswordCapture bool
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

func (m *RegistrationManager) SetDispatcher(d events.Dispatcher) {
	m.dispatcher = d
}

func (m *RegistrationManager) SetSchema(s identity.Schema) {
	m.schema = s
}

func (m *RegistrationManager) SetLinker(l Linker) {
	m.linker = l
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

	// 2.5 Auto-Unification (Implicit Linking)
	if m.linker != nil {
		existing, err := m.linker.FindExisting(ctx, traits)
		if err == nil && existing != nil {
			// FOUND a matching identity with verified traits!
			
			// BLOCK if it's a password registration and policy is enabled
			if method == "password" && m.PreventPasswordCapture {
				return nil, ErrIdentityAlreadyExists
			}

			// Otherwise, try to link it.
			err := m.linker.Link(ctx, existing, method, "", secret)
			if err == nil {
				return existing, nil
			}
			// If linking failed specifically, we continue to regular registration? 
			// Or return error? For security, we might want to fail or prompt for "Connect accounts".
		}
	}

	// 3. Delegate to strategy
	ident, err := strategy.Register(ctx, traits, secret)
	if err != nil {
		if m.auditStore != nil {
			m.auditStore.SaveEvent(ctx, &audit.AuditEvent{
				Type:    string(events.TopicIdentityFailure),
				Status:  "failure",
				Message: err.Error(),
			})
		}
		if m.dispatcher != nil {
			event := events.NewEvent(events.TopicIdentityFailure, events.CodeBadRequest)
			m.dispatcher.Dispatch(ctx, event)
		}
		return nil, err
	}

	if m.auditStore != nil {
		m.auditStore.SaveEvent(ctx, &audit.AuditEvent{
			Type:   string(events.TopicIdentityCreated),
			Status: "success",
		})
	}

	if m.dispatcher != nil {
		event := events.NewEvent(events.TopicIdentityCreated, events.CodeCreated)
		if fi, ok := ident.(FlowIdentity); ok {
			event.SubjectID = fi.GetID()
		}
		m.dispatcher.Dispatch(ctx, event)
	}

	// 3. Post-hooks
	for _, h := range m.postHooks {
		if err := h(ctx, ident); err != nil {
			return nil, err
		}
	}

	return ident, nil
}
