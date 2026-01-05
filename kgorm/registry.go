package kgorm

import (
	"fmt"
	"sync"

	"github.com/getkayan/kayan/core/domain"
	"gorm.io/gorm"
)

// DialectorOpener is an alias for a function that returns a gorm.Dialector for a given DSN.
type DialectorOpener = func(string) gorm.Dialector

var (
	registryMu sync.RWMutex
	providers  = make(map[string]any)
)

// Register adds a new storage provider to the registry.
// Provider can be a DialectorOpener (for GORM) or a custom factory function
// matching func(string, any) (domain.Storage, error).
func Register(name string, provider any) {
	registryMu.Lock()
	defer registryMu.Unlock()
	providers[name] = provider
}

// NewStorage creates a new storage implementation based on the registered name.
func NewStorage(name string, dsn string, extra any, models ...any) (domain.Storage, error) {
	registryMu.RLock()
	provider, ok := providers[name]
	registryMu.RUnlock()

	if !ok {
		return nil, fmt.Errorf("gorm: unknown storage provider %q", name)
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

		repo := NewRepository(db)
		if err := repo.AutoMigrate(models...); err != nil {
			return nil, err
		}

		return repo, nil
	}

	// Case 2: Custom Factory Function
	if factory, ok := provider.(func(string, any) (domain.Storage, error)); ok {
		return factory(dsn, extra)
	}

	return nil, fmt.Errorf("gorm: provider %q registered with incompatible type (expected DialectorOpener or generic factory)", name)
}
