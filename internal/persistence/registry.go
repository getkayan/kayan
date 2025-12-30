package persistence

import (
	"fmt"
	"sync"

	"github.com/getkayan/kayan/internal/domain"
)

// Factory is a function that creates a new Storage implementation.
type Factory func(dsn string, extra interface{}) (domain.Storage, error)

var (
	registryMu sync.RWMutex
	registry   = make(map[string]Factory)
)

// Register adds a new storage factory to the registry.
func Register(name string, factory Factory) {
	registryMu.Lock()
	defer registryMu.Unlock()
	registry[name] = factory
}

// NewStorage creates a new storage implementation based on the registered name.
func NewStorage(name string, dsn string, extra interface{}) (domain.Storage, error) {
	registryMu.RLock()
	factory, ok := registry[name]
	registryMu.RUnlock()

	if !ok {
		return nil, fmt.Errorf("persistence: unknown storage provider %q", name)
	}

	return factory(dsn, extra)
}
