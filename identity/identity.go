package identity

import (
	"database/sql/driver"
	"errors"
	"time"

	"gorm.io/gorm"
)

// JSON is a custom type for handling JSON data in GORM.
type JSON []byte

func (j JSON) Value() (driver.Value, error) {
	if len(j) == 0 {
		return nil, nil
	}
	return string(j), nil
}

func (j *JSON) Scan(value interface{}) error {
	if value == nil {
		*j = nil
		return nil
	}
	switch v := value.(type) {
	case []byte:
		*j = append((*j)[0:0], v...)
	case string:
		*j = []byte(v)
	default:
		return errors.New("invalid type for JSON")
	}
	return nil
}

// Identity represents a user identity with flexible ID type T.
type Identity[T any] struct {
	ID        T              `gorm:"primaryKey" json:"id"`
	Traits    JSON           `gorm:"type:json" json:"traits"`
	CreatedAt time.Time      `json:"created_at"`
	UpdatedAt time.Time      `json:"updated_at"`
	DeletedAt gorm.DeletedAt `gorm:"index" json:"-"`

	Credentials []Credential[T] `gorm:"foreignKey:IdentityID" json:"-"`
}

func (Identity[T]) TableName() string { return "identities" }

// Credential represents an authentication credential with flexible ID type T.
type Credential[T any] struct {
	ID         T         `gorm:"primaryKey" json:"id"`
	IdentityID T         `gorm:"index" json:"identity_id"`
	Type       string    `gorm:"index" json:"type"`
	Identifier string    `gorm:"index" json:"identifier"`
	Secret     string    `json:"-"`
	Config     JSON      `gorm:"type:json" json:"config"`
	CreatedAt  time.Time `json:"created_at"`
	UpdatedAt  time.Time `json:"updated_at"`
}

func (Credential[T]) TableName() string { return "credentials" }

// Session represents an authenticated session with flexible ID type T.
type Session[T any] struct {
	ID         T         `gorm:"primaryKey" json:"id"`
	IdentityID T         `gorm:"index" json:"identity_id"`
	ExpiresAt  time.Time `json:"expires_at"`
	IssuedAt   time.Time `json:"issued_at"`
	Active     bool      `json:"active"`
}

func (Session[T]) TableName() string { return "sessions" }
