package persistence

import (
	"github.com/getkayan/kayan/identity"
	"github.com/glebarez/sqlite"
	"gorm.io/driver/mysql"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

type Repository[T any] struct {
	db *gorm.DB
}

func NewRepository[T any](db *gorm.DB) *Repository[T] {
	return &Repository[T]{db: db}
}

func init() {
	Register("sqlite", sqlite.Open)
	Register("postgres", postgres.Open)
	Register("mysql", mysql.Open)
}

func (r *Repository[T]) AutoMigrate() error {
	return r.db.AutoMigrate(
		&identity.Identity[T]{},
		&identity.Credential[T]{},
		&identity.Session[T]{},
	)
}

func (r *Repository[T]) CreateIdentity(id *identity.Identity[T]) error {
	return r.db.Create(id).Error
}

func (r *Repository[T]) GetIdentity(id T) (*identity.Identity[T], error) {
	var ident identity.Identity[T]
	if err := r.db.Preload("Credentials").First(&ident, "id = ?", id).Error; err != nil {
		return nil, err
	}
	return &ident, nil
}

func (r *Repository[T]) GetCredentialByIdentifier(identifier string, method string) (*identity.Credential[T], error) {
	var cred identity.Credential[T]
	if err := r.db.Where("identifier = ? AND type = ?", identifier, method).First(&cred).Error; err != nil {
		return nil, err
	}
	return &cred, nil
}

func (r *Repository[T]) CreateSession(s *identity.Session[T]) error {
	return r.db.Create(s).Error
}

func (r *Repository[T]) GetSession(id T) (*identity.Session[T], error) {
	var s identity.Session[T]
	if err := r.db.First(&s, "id = ?", id).Error; err != nil {
		return nil, err
	}
	return &s, nil
}

func (r *Repository[T]) DeleteSession(id T) error {
	return r.db.Delete(&identity.Session[T]{}, "id = ?", id).Error
}
