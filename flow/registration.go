package flow

import (
	"context"
	"fmt"

	"github.com/getkayan/kayan/identity"
)

type RegistrationManager[T any] struct {
	repo       IdentityRepository[T]
	strategies map[string]RegistrationStrategy[T]
	preHooks   []Hook[T]
	postHooks  []Hook[T]
}

func NewRegistrationManager[T any](repo IdentityRepository[T]) *RegistrationManager[T] {
	return &RegistrationManager[T]{
		repo:       repo,
		strategies: make(map[string]RegistrationStrategy[T]),
	}
}

func (m *RegistrationManager[T]) RegisterStrategy(s RegistrationStrategy[T]) {
	m.strategies[s.ID()] = s
}

func (m *RegistrationManager[T]) AddPreHook(h Hook[T])  { m.preHooks = append(m.preHooks, h) }
func (m *RegistrationManager[T]) AddPostHook(h Hook[T]) { m.postHooks = append(m.postHooks, h) }

func (m *RegistrationManager[T]) Submit(ctx context.Context, method string, traits identity.JSON, secret string) (*identity.Identity[T], error) {
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

	// 2. Delegate to strategy
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
