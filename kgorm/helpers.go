package kgorm

import (
	"github.com/getkayan/kayan/core/config"
	"github.com/getkayan/kayan/core/flow"
	"github.com/getkayan/kayan/core/identity"
	"github.com/getkayan/kayan/core/session"
	"gorm.io/gorm"
)

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
	return flow.NewLoginManager(repo)
}

// NewDefaultSessionManager creates a SessionManager using the default ID type and GORM.
func NewDefaultSessionManager(db *gorm.DB) *session.Manager {
	repo := NewRepository(db)
	return session.NewManager(session.NewDatabaseStrategy(repo))
}

// NewDefaultOIDCManager creates an OIDCManager using the default identity and GORM.
func NewDefaultOIDCManager(db *gorm.DB, configs map[string]config.OIDCProvider) (*flow.OIDCManager, error) {
	repo := NewRepository(db)
	return flow.NewOIDCManager(repo, configs, func() any {
		return &identity.Identity{}
	})
}
