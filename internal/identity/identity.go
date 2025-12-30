package identity

import (
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

// Identity represents a user or actor in the system.
type Identity struct {
	ID        uuid.UUID      `gorm:"type:uuid;primaryKey" json:"id"`
	Traits    JSON           `gorm:"type:json" json:"traits"`
	CreatedAt time.Time      `json:"created_at"`
	UpdatedAt time.Time      `json:"updated_at"`
	DeletedAt gorm.DeletedAt `gorm:"index" json:"-"`

	Credentials []Credential `gorm:"foreignKey:IdentityID" json:"-"`
}

// JSON is a simple wrapper for json/byte slice to work with GORM
type JSON []byte

func (j *JSON) Scan(value interface{}) error {
	*j = JSON(value.([]byte))
	return nil
}

func (j JSON) Value() (interface{}, error) {
	if len(j) == 0 {
		return nil, nil
	}
	return string(j), nil
}

// Credential represents an authentication method for an identity (e.g., password, oidc).
type Credential struct {
	ID         uuid.UUID `gorm:"type:uuid;primaryKey" json:"id"`
	IdentityID uuid.UUID `gorm:"type:uuid;index" json:"identity_id"`
	Type       string    `gorm:"index" json:"type"` // e.g., "password", "oidc"
	Identifier string    `gorm:"index" json:"identifier"`
	Secret     string    `json:"-"` // Hashed password or token
	Config     JSON      `gorm:"type:json" json:"config"`
	CreatedAt  time.Time `json:"created_at"`
	UpdatedAt  time.Time `json:"updated_at"`
}

// Session represents an authenticated session.
type Session struct {
	ID         uuid.UUID `gorm:"type:uuid;primaryKey" json:"id"`
	IdentityID uuid.UUID `gorm:"type:uuid;index" json:"identity_id"`
	ExpiresAt  time.Time `json:"expires_at"`
	IssuedAt   time.Time `json:"issued_at"`
	Active     bool      `json:"active"`
}
