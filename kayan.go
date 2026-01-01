package kayan

import (
	"github.com/getkayan/kayan/config"
	"github.com/getkayan/kayan/flow"
	"github.com/getkayan/kayan/identity"
	"github.com/getkayan/kayan/persistence"
	"github.com/getkayan/kayan/session"
	"github.com/google/uuid"
	"gorm.io/gorm"
)

// Default types for convenience
type ID = uuid.UUID
type Identity = identity.DefaultIdentity

// NewDefaultRegistrationManager creates a RegistrationManager using the default identity.
func NewDefaultRegistrationManager(db *gorm.DB) *flow.RegistrationManager {
	repo := persistence.NewRepository(db)
	return flow.NewRegistrationManager(repo, func() any {
		return &identity.Identity{}
	})
}

// NewDefaultLoginManager creates a LoginManager using the default identity.
func NewDefaultLoginManager(db *gorm.DB) *flow.LoginManager {
	repo := persistence.NewRepository(db)
	return flow.NewLoginManager(repo)
}

// NewDefaultSessionManager creates a SessionManager using the default ID type.
func NewDefaultSessionManager(db *gorm.DB) *session.Manager {
	repo := persistence.NewRepository(db)
	return session.NewManager(repo)
}

// NewDefaultOIDCManager creates an OIDCManager using the default identity.
func NewDefaultOIDCManager(db *gorm.DB, configs map[string]config.OIDCProvider) (*flow.OIDCManager, error) {
	repo := persistence.NewRepository(db)
	return flow.NewOIDCManager(repo, configs, func() any {
		return &identity.Identity{}
	})
}
