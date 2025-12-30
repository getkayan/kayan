package persistence

import (
	"github.com/getkayan/kayan/internal/domain"
	"github.com/getkayan/kayan/internal/identity"
	"github.com/glebarez/sqlite"
	"gorm.io/driver/mysql"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

type Repository struct {
	db *gorm.DB
}

func init() {
	Register("sqlite", GORMFactory(sqlite.Open))
	Register("postgres", GORMFactory(postgres.Open))
	Register("mysql", GORMFactory(mysql.Open))
}

// GORMFactory returns a factory that uses GORM with a specific dialector opener.
func GORMFactory(opener func(string) gorm.Dialector) Factory {
	return func(dsn string, extra interface{}) (domain.Storage, error) {
		gormConfig, _ := extra.(*gorm.Config)
		if gormConfig == nil {
			gormConfig = &gorm.Config{}
		}

		db, err := gorm.Open(opener(dsn), gormConfig)
		if err != nil {
			return nil, err
		}

		repo := &Repository{db: db}
		// We can't easily pass skipAutoMigrate here without changing Factory signature or using a struct
		// For now, we auto-migrate by default in GORM factory
		if err := repo.AutoMigrate(); err != nil {
			return nil, err
		}

		return repo, nil
	}
}

func (r *Repository) AutoMigrate() error {
	return r.db.AutoMigrate(
		&identity.Identity{},
		&identity.Credential{},
		&identity.Session{},
	)
}

func (r *Repository) CreateIdentity(id *identity.Identity) error {
	return r.db.Create(id).Error
}

func (r *Repository) GetIdentity(id string) (*identity.Identity, error) {
	var ident identity.Identity
	if err := r.db.Preload("Credentials").First(&ident, "id = ?", id).Error; err != nil {
		return nil, err
	}
	return &ident, nil
}

func (r *Repository) GetCredentialByIdentifier(identifier string, method string) (*identity.Credential, error) {
	var cred identity.Credential
	if err := r.db.Where("identifier = ? AND type = ?", identifier, method).First(&cred).Error; err != nil {
		return nil, err
	}
	return &cred, nil
}

func (r *Repository) CreateSession(s *identity.Session) error {
	return r.db.Create(s).Error
}

func (r *Repository) GetSession(id string) (*identity.Session, error) {
	var s identity.Session
	if err := r.db.First(&s, "id = ?", id).Error; err != nil {
		return nil, err
	}
	return &s, nil
}

func (r *Repository) DeleteSession(id string) error {
	return r.db.Delete(&identity.Session{}, "id = ?", id).Error
}
