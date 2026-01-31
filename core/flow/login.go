package flow

import (
	"context"
	"errors"
	"fmt"
	"log"
	"sync"

	"github.com/getkayan/kayan/core/audit"
	"github.com/getkayan/kayan/core/domain"
	"github.com/getkayan/kayan/core/identity"
)

type LoginManager struct {
	repo       IdentityRepository
	auditStore audit.AuditStore

	// Dynamic Config
	strategyStore    domain.StrategyStore
	strategyRegistry *StrategyRegistry

	mu         sync.RWMutex
	strategies map[string]LoginStrategy
	preHooks   []Hook
	postHooks  []Hook
	factory    func() any
}

var ErrMFARequired = errors.New("login: mfa required")

func NewLoginManager(repo IdentityRepository) *LoginManager {
	store, ok := repo.(audit.AuditStore)
	var auditStore audit.AuditStore
	if ok {
		auditStore = store
	}

	return &LoginManager{
		repo:             repo,
		auditStore:       auditStore,
		strategies:       make(map[string]LoginStrategy),
		strategyRegistry: NewStrategyRegistry(),
	}
}

func (m *LoginManager) SetStrategyStore(store domain.StrategyStore) {
	m.strategyStore = store
}

func (m *LoginManager) Registry() *StrategyRegistry {
	return m.strategyRegistry
}

// ReloadStrategies fetches configs from the store and rebuilds strategies.
func (m *LoginManager) ReloadStrategies(ctx context.Context) error {
	if m.strategyStore == nil {
		return nil
	}

	configs, err := m.strategyStore.GetStrategies(ctx)
	if err != nil {
		return err
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	// Clear existing (dynamic ones)? Or just overwrite.
	// For safety, let's keep manually registered ones if they don't collide.
	// But usually dynamic overrides static.

	for _, cfg := range configs {
		if !cfg.Enabled {
			delete(m.strategies, cfg.ID)
			continue
		}

		strategy, err := m.strategyRegistry.Build(cfg)
		if err != nil {
			// Log error but continue?
			log.Printf("login: failed to build strategy %s: %v", cfg.ID, err)
			continue
		}
		m.strategies[cfg.ID] = strategy
	}
	return nil
}

func (m *LoginManager) SetFactory(f func() any) { m.factory = f }

func (m *LoginManager) FindIdentity(ctx context.Context, identifier string) (any, error) {
	if m.factory == nil {
		return nil, fmt.Errorf("login: factory not set")
	}
	return m.repo.FindIdentity(m.factory, map[string]any{"identifier": identifier})
}

// VerifyMFA checks the second factor (e.g. TOTP) for an identity.
func (m *LoginManager) VerifyMFA(ctx context.Context, ident any, code string) (bool, error) {
	i, ok := ident.(*identity.Identity)
	if !ok {
		return false, fmt.Errorf("login: invalid identity type for MFA")
	}

	if !i.MFAEnabled {
		return true, nil
	}

	strategy := &TOTPStrategy{}
	return strategy.Verify(i.MFASecret, code), nil
}

func (m *LoginManager) RegisterStrategy(s LoginStrategy) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.strategies[s.ID()] = s
}

func (m *LoginManager) AddPreHook(h Hook)  { m.preHooks = append(m.preHooks, h) }
func (m *LoginManager) AddPostHook(h Hook) { m.postHooks = append(m.postHooks, h) }

func (m *LoginManager) InitiateLogin(ctx context.Context, method, identifier string) (any, error) {
	m.mu.RLock()
	strategy, ok := m.strategies[method]
	m.mu.RUnlock()

	if !ok {
		// Try to reload just in case? Or rely on periodic/startup reload.
		return nil, fmt.Errorf("login: unknown method %q", method)
	}

	initiator, ok := strategy.(Initiator)
	if !ok {
		return nil, fmt.Errorf("login: method %q does not support initiation", method)
	}

	result, err := initiator.Initiate(ctx, identifier)
	if err != nil {
		return nil, err
	}

	if m.auditStore != nil {
		m.auditStore.SaveEvent(ctx, &audit.AuditEvent{
			Type:    "identity.login.initiate",
			ActorID: identifier,
			Status:  "success",
			Message: fmt.Sprintf("Initiated login using %s", method),
		})
	}

	return result, nil
}

func (m *LoginManager) Authenticate(ctx context.Context, method, identifier, secret string) (any, error) {
	m.mu.RLock()
	strategy, ok := m.strategies[method]
	m.mu.RUnlock()

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
		if m.auditStore != nil {
			m.auditStore.SaveEvent(ctx, &audit.AuditEvent{
				Type:    "identity.login.failure",
				ActorID: identifier,
				Status:  "failure",
				Message: err.Error(),
			})
		}
		return nil, err
	}

	// Check if MFA required... (same as before)
	i, ok := ident.(*identity.Identity)
	if ok && i.MFAEnabled {
		if m.auditStore != nil {
			m.auditStore.SaveEvent(ctx, &audit.AuditEvent{
				Type:    "identity.login.mfa_challenge",
				ActorID: identifier,
				Status:  "success",
				Message: "First step success, MFA required",
			})
		}
		return ident, ErrMFARequired
	}

	if m.auditStore != nil {
		m.auditStore.SaveEvent(ctx, &audit.AuditEvent{
			Type:    "identity.login.success",
			ActorID: identifier,
			Status:  "success",
			Message: "Login successful",
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
