package flow

import (
	"context"
	"errors"

	"github.com/getkayan/kayan/internal/identity"
)

type LoginManager struct {
	repo       IdentityRepository
	strategies map[string]LoginStrategy
	preHooks   []Hook
	postHooks  []Hook
}

func NewLoginManager(repo IdentityRepository) *LoginManager {
	return &LoginManager{
		repo:       repo,
		strategies: make(map[string]LoginStrategy),
	}
}

func (m *LoginManager) RegisterStrategy(s LoginStrategy) {
	m.strategies[s.ID()] = s
}

func (m *LoginManager) AddPreHook(h Hook)  { m.preHooks = append(m.preHooks, h) }
func (m *LoginManager) AddPostHook(h Hook) { m.postHooks = append(m.postHooks, h) }

func (m *LoginManager) Authenticate(ctx context.Context, method, identifier, secret string) (*identity.Identity, error) {
	strategy, ok := m.strategies[method]
	if !ok {
		return nil, errors.New("login: unknown method")
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
