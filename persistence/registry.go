package persistence

import (
	"fmt"
	"sync"

	"github.com/getkayan/kayan/domain"
	"gorm.io/gorm"
)

// DialectorOpener is an alias for a function that returns a gorm.Dialector for a given DSN.
type DialectorOpener = func(string) gorm.Dialector

var (
	registryMu sync.RWMutex
	providers  = make(map[string]interface{})
)

// Register adds a new storage provider to the registry.
// Provider can be a DialectorOpener (for GORM) or a custom factory function
// matching func(string, interface{}) (domain.Storage[T], error).
func Register(name string, provider interface{}) {
	registryMu.Lock()
	defer registryMu.Unlock()
	providers[name] = provider
}

// NewStorage creates a new storage implementation based on the registered name.
func NewStorage[T any](name string, dsn string, extra interface{}) (domain.Storage[T], error) {
	registryMu.RLock()
	provider, ok := providers[name]
	registryMu.RUnlock()

	if !ok {
		return nil, fmt.Errorf("persistence: unknown storage provider %q", name)
	}

	// Case 1: Standard GORM DialectorOpener
	if opener, ok := provider.(DialectorOpener); ok {
		gormConfig, _ := extra.(*gorm.Config)
		if gormConfig == nil {
			gormConfig = &gorm.Config{}
		}

		db, err := gorm.Open(opener(dsn), gormConfig)
		if err != nil {
			return nil, err
		}

		repo := NewRepository[T](db)
		if err := repo.AutoMigrate(); err != nil {
			return nil, err
		}

		return repo, nil
	}

	// Case 2: Custom Factory Function
	if factory, ok := provider.(func(string, interface{}) (domain.Storage[T], error)); ok {
		return factory(dsn, extra)
	}

	return nil, fmt.Errorf("persistence: provider %q registered with incompatible type (expected DialectorOpener or generic factory)", name)
}
