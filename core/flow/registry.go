package flow

import (
	"fmt"
	"sort"
	"sync"

	"github.com/getkayan/kayan/core/domain"
)

// StrategyFactory is a function that creates a LoginStrategy from a config.
type StrategyFactory func(config *domain.StrategyConfig) (LoginStrategy, error)

// RegistrationStrategyFactory is a function that creates a RegistrationStrategy from a config.
type RegistrationStrategyFactory func(config *domain.StrategyConfig) (RegistrationStrategy, error)

// StrategyRegistry maintains a map of factory functions for creating strategies.
type StrategyRegistry struct {
	mu           sync.RWMutex
	factories    map[string]StrategyFactory
	regFactories map[string]RegistrationStrategyFactory
}

func NewStrategyRegistry() *StrategyRegistry {
	return &StrategyRegistry{
		factories:    make(map[string]StrategyFactory),
		regFactories: make(map[string]RegistrationStrategyFactory),
	}
}

// RegisterFactory registers a factory function for a specific login strategy type (e.g. "password", "oidc").
func (r *StrategyRegistry) RegisterFactory(typeKey string, factory StrategyFactory) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.factories[typeKey] = factory
}

// RegisterRegistrationFactory registers a factory function for a specific registration strategy type.
func (r *StrategyRegistry) RegisterRegistrationFactory(typeKey string, factory RegistrationStrategyFactory) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.regFactories[typeKey] = factory
}

// Build creates a login strategy instance from a configuration.
func (r *StrategyRegistry) Build(config *domain.StrategyConfig) (LoginStrategy, error) {
	r.mu.RLock()
	factory, ok := r.factories[config.Type]
	r.mu.RUnlock()

	if !ok {
		return nil, fmt.Errorf("registry: unknown strategy type %q", config.Type)
	}

	return factory(config)
}

// BuildRegistration creates a registration strategy instance from a configuration.
func (r *StrategyRegistry) BuildRegistration(config *domain.StrategyConfig) (RegistrationStrategy, error) {
	r.mu.RLock()
	factory, ok := r.regFactories[config.Type]
	r.mu.RUnlock()

	if !ok {
		return nil, fmt.Errorf("registry: unknown registration strategy type %q", config.Type)
	}

	return factory(config)
}

// ListFactories returns a sorted list of all registered factory type keys (login and registration combined).
func (r *StrategyRegistry) ListFactories() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()

	seen := make(map[string]bool)
	for k := range r.factories {
		seen[k] = true
	}
	for k := range r.regFactories {
		seen[k] = true
	}

	keys := make([]string, 0, len(seen))
	for k := range seen {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
