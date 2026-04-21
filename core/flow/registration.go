package flow

import (
	"context"
	"fmt"
	"sync"

	"github.com/getkayan/kayan/core/audit"
	"github.com/getkayan/kayan/core/events"
	"github.com/getkayan/kayan/core/identity"
)

type RegistrationManager struct {
	mu                     sync.RWMutex
	repo                   IdentityRepository
	auditStore             audit.AuditStore
	dispatcher             events.Dispatcher
	strategies             map[string]RegistrationStrategy
	preHooks               []Hook
	postHooks              []Hook
	factory                func() any
	schema                 identity.Schema
	linker                 Linker
	preventPasswordCapture bool
}

// RegistrationOption configures a RegistrationManager.
type RegistrationOption func(*RegistrationManager)

// WithRegDispatcher sets the event dispatcher.
func WithRegDispatcher(d events.Dispatcher) RegistrationOption {
	return func(m *RegistrationManager) { m.dispatcher = d }
}

// WithSchema sets the trait validation schema.
func WithSchema(s identity.Schema) RegistrationOption {
	return func(m *RegistrationManager) { m.schema = s }
}

// WithLinker sets the account unification linker.
func WithLinker(l Linker) RegistrationOption {
	return func(m *RegistrationManager) { m.linker = l }
}

// WithRegPreHook adds a pre-registration hook.
func WithRegPreHook(h Hook) RegistrationOption {
	return func(m *RegistrationManager) { m.preHooks = append(m.preHooks, h) }
}

// WithRegPostHook adds a post-registration hook.
func WithRegPostHook(h Hook) RegistrationOption {
	return func(m *RegistrationManager) { m.postHooks = append(m.postHooks, h) }
}

// WithPreventPasswordCapture prevents password registration when an identity already exists.
func WithPreventPasswordCapture() RegistrationOption {
	return func(m *RegistrationManager) { m.preventPasswordCapture = true }
}

func NewRegistrationManager(repo IdentityRepository, factory func() any, opts ...RegistrationOption) *RegistrationManager {
	store, ok := repo.(audit.AuditStore)
	var auditStore audit.AuditStore
	if ok {
		auditStore = store
	}

	m := &RegistrationManager{
		repo:       repo,
		auditStore: auditStore,
		strategies: make(map[string]RegistrationStrategy),
		factory:    factory,
	}
	for _, opt := range opts {
		opt(m)
	}
	return m
}

func (m *RegistrationManager) RegisterStrategy(s RegistrationStrategy) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.strategies[s.ID()] = s
}

// Deprecated: Use WithRegDispatcher option instead.
func (m *RegistrationManager) SetDispatcher(d events.Dispatcher) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.dispatcher = d
}

// Deprecated: Use WithSchema option instead.
func (m *RegistrationManager) SetSchema(s identity.Schema) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.schema = s
}

// Deprecated: Use WithLinker option instead.
func (m *RegistrationManager) SetLinker(l Linker) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.linker = l
}

func (m *RegistrationManager) AddPreHook(h Hook) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.preHooks = append(m.preHooks, h)
}

func (m *RegistrationManager) AddPostHook(h Hook) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.postHooks = append(m.postHooks, h)
}

func (m *RegistrationManager) Submit(ctx context.Context, method string, traits identity.JSON, secret string) (any, error) {
	m.mu.RLock()
	strategy, ok := m.strategies[method]
	preHooks := append([]Hook(nil), m.preHooks...)
	postHooks := append([]Hook(nil), m.postHooks...)
	auditStore := m.auditStore
	dispatcher := m.dispatcher
	schema := m.schema
	linker := m.linker
	preventPasswordCapture := m.preventPasswordCapture
	m.mu.RUnlock()

	if !ok {
		return nil, fmt.Errorf("registration: unknown method %q", method)
	}

	// 1. Pre-hooks
	for _, h := range preHooks {
		if err := h(ctx, nil); err != nil {
			return nil, err
		}
	}

	// 2. Schema Validation
	if schema != nil {
		if err := schema.Validate(traits); err != nil {
			return nil, fmt.Errorf("registration: validation failed: %v", err)
		}
	}

	// 2.5 Auto-Unification (Implicit Linking)
	if linker != nil {
		existing, err := linker.FindExisting(ctx, traits)
		if err == nil && existing != nil {
			if method == "password" && preventPasswordCapture {
				return nil, ErrIdentityAlreadyExists
			}

			if method == "password" {
				return existing, nil
			}

			err := linker.Link(ctx, existing, method, "", secret)
			if err == nil {
				return existing, nil
			}
		}
	}

	// 3. Delegate to strategy
	ident, err := strategy.Register(ctx, traits, secret)
	if err != nil {
		if auditStore != nil {
			auditStore.SaveEvent(ctx, &audit.AuditEvent{
				Type:    string(events.TopicIdentityFailure),
				Status:  "failure",
				Message: err.Error(),
			})
		}
		if dispatcher != nil {
			event := events.NewEvent(events.TopicIdentityFailure, events.CodeBadRequest)
			dispatcher.Dispatch(ctx, event)
		}
		return nil, err
	}

	if auditStore != nil {
		auditStore.SaveEvent(ctx, &audit.AuditEvent{
			Type:   string(events.TopicIdentityCreated),
			Status: "success",
		})
	}

	if dispatcher != nil {
		event := events.NewEvent(events.TopicIdentityCreated, events.CodeCreated)
		if fi, ok := ident.(FlowIdentity); ok {
			event.SubjectID = fi.GetID()
		}
		dispatcher.Dispatch(ctx, event)
	}

	// 3. Post-hooks
	for _, h := range postHooks {
		if err := h(ctx, ident); err != nil {
			return nil, err
		}
	}

	return ident, nil
}
