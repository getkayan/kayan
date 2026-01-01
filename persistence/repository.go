package persistence

import (
	"github.com/getkayan/kayan/identity"
	"github.com/glebarez/sqlite"
	"gorm.io/driver/mysql"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

type Repository struct {
	db *gorm.DB
}

func NewRepository(db *gorm.DB) *Repository {
	return &Repository{db: db}
}

func (r *Repository) DB() *gorm.DB {
	return r.db
}

func init() {
	Register("sqlite", sqlite.Open)
	Register("postgres", postgres.Open)
	Register("mysql", mysql.Open)
}

func (r *Repository) AutoMigrate(models ...any) error {
	// Identity, Credential, and Session are base models that should always be migrated
	baseModels := []any{
		&identity.Identity{},
		&identity.Credential{},
		&identity.Session{},
	}
	allModels := append(baseModels, models...)
	return r.db.AutoMigrate(allModels...)
}

func (r *Repository) CreateIdentity(ident any) error {
	return r.db.Create(ident).Error
}

func (r *Repository) GetIdentity(factory func() any, id any) (any, error) {
	ident := factory()
	if err := r.db.First(ident, "id = ?", id).Error; err != nil {
		return nil, err
	}
	return ident, nil
}

func (r *Repository) FindIdentity(factory func() any, query map[string]any) (any, error) {
	ident := factory()
	if err := r.db.Where(query).First(ident).Error; err != nil {
		return nil, err
	}
	return ident, nil
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

func (r *Repository) GetSession(id any) (*identity.Session, error) {
	var s identity.Session
	if err := r.db.First(&s, "id = ?", id).Error; err != nil {
		return nil, err
	}
	return &s, nil
}

func (r *Repository) DeleteSession(id any) error {
	return r.db.Delete(&identity.Session{}, "id = ?", id).Error
}
