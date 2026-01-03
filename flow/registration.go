package flow

import (
	"context"
	"fmt"

	"github.com/getkayan/kayan/identity"
)

type RegistrationManager struct {
	repo       IdentityRepository
	strategies map[string]RegistrationStrategy
	preHooks   []Hook
	postHooks  []Hook
	factory    func() any
	schema     identity.Schema
}

func NewRegistrationManager(repo IdentityRepository, factory func() any) *RegistrationManager {
	return &RegistrationManager{
		repo:       repo,
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
		return nil, err
	}

	// 3. Post-hooks
	for _, h := range m.postHooks {
		if err := h(ctx, ident); err != nil {
			return nil, err
		}
	}

	return ident, nil
}
