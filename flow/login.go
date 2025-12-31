package flow

import (
	"context"
	"fmt"

	"github.com/getkayan/kayan/identity"
)

type LoginManager[T any] struct {
	repo       IdentityRepository[T]
	strategies map[string]LoginStrategy[T]
	preHooks   []Hook[T]
	postHooks  []Hook[T]
}

func NewLoginManager[T any](repo IdentityRepository[T]) *LoginManager[T] {
	return &LoginManager[T]{
		repo:       repo,
		strategies: make(map[string]LoginStrategy[T]),
	}
}

func (m *LoginManager[T]) RegisterStrategy(s LoginStrategy[T]) {
	m.strategies[s.ID()] = s
}

func (m *LoginManager[T]) AddPreHook(h Hook[T])  { m.preHooks = append(m.preHooks, h) }
func (m *LoginManager[T]) AddPostHook(h Hook[T]) { m.postHooks = append(m.postHooks, h) }

func (m *LoginManager[T]) Authenticate(ctx context.Context, method, identifier, secret string) (*identity.Identity[T], error) {
	strategy, ok := m.strategies[method]
	if !ok {
		return nil, fmt.Errorf("login: unknown method %q", method)
	}

	// 1. Pre-hooks
	for _, h := range m.preHooks {
		if err := h(ctx, nil); err != nil {
			return nil, err
		}
	}

	// 2. Delegate to strategy
	ident, err := strategy.Authenticate(ctx, identifier, secret)
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
