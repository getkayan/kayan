package flow

import (
	"fmt"
	"sync"

	"github.com/getkayan/kayan/core/domain"
)

// StrategyFactory is a function that creates a LoginStrategy from a config.
type StrategyFactory func(config *domain.StrategyConfig) (LoginStrategy, error)

// StrategyRegistry maintains a map of factory functions for creating strategies.
type StrategyRegistry struct {
	mu        sync.RWMutex
	factories map[string]StrategyFactory
}

func NewStrategyRegistry() *StrategyRegistry {
	return &StrategyRegistry{
		factories: make(map[string]StrategyFactory),
	}
}

// RegisterFactory registers a factory function for a specific strategy type (e.g. "password", "oidc").
func (r *StrategyRegistry) RegisterFactory(typeKey string, factory StrategyFactory) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.factories[typeKey] = factory
}

// Build creates a strategy instance from a configuration.
func (r *StrategyRegistry) Build(config *domain.StrategyConfig) (LoginStrategy, error) {
	r.mu.RLock()
	factory, ok := r.factories[config.Type]
	r.mu.RUnlock()

	if !ok {
		return nil, fmt.Errorf("registry: unknown strategy type %q", config.Type)
	}

	return factory(config)
}
