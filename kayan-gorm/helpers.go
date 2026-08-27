package gormstore

import (
	"errors"
	"fmt"

	"github.com/getkayan/kayan/core/domain"
	"github.com/getkayan/kayan/core/flow"
	"github.com/getkayan/kayan/core/identity"
	"github.com/getkayan/kayan/core/session"
	"gorm.io/gorm"
)

func storageError(operation string, err error) error {
	if err == nil {
		return nil
	}
	portable := error(nil)
	switch {
	case errors.Is(err, gorm.ErrRecordNotFound):
		portable = domain.ErrNotFound
	case errors.Is(err, gorm.ErrDuplicatedKey):
		portable = domain.ErrConflict
	}
	if portable != nil {
		return fmt.Errorf("gormstore: %s: %w", operation, errors.Join(portable, err))
	}
	return fmt.Errorf("gormstore: %s: %w", operation, err)
}

// NewDefaultRegistrationManager creates a RegistrationManager using the default identity and GORM.
func NewDefaultRegistrationManager(db *gorm.DB) *flow.RegistrationManager {
	repo := NewRepository(db)
	return flow.NewRegistrationManager(repo, func() any {
		return &identity.Identity{}
	})
}

// NewDefaultLoginManager creates a LoginManager using the default identity and GORM.
func NewDefaultLoginManager(db *gorm.DB) *flow.LoginManager {
	repo := NewRepository(db)
	return flow.NewLoginManager(repo, func() any {
		return &identity.Identity{}
	})
}

// NewDefaultSessionManager creates a SessionManager using the default ID type and GORM.
func NewDefaultSessionManager(db *gorm.DB) *session.Manager {
	repo := NewRepository(db)
	return session.NewManager(session.NewDatabaseStrategy(repo))
}
