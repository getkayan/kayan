package gormstore

import (
	"time"

	"github.com/getkayan/kayan/core/audit"
	"github.com/getkayan/kayan/core/domain"
	"github.com/getkayan/kayan/core/identity"
)

type gormAuditEvent struct {
	ID        string `gorm:"primaryKey"`
	Type      string `gorm:"index"`
	ActorID   string `gorm:"index"`
	SubjectID string `gorm:"index"`
	Status    string `gorm:"index"`
	Message   string
	Metadata  identity.JSON `gorm:"type:json"`
	CreatedAt time.Time     `gorm:"index"`

	// Compliance fields
	TenantID     string `gorm:"index"`
	IPAddress    string `gorm:"index"`
	UserAgent    string
	DeviceID     string        `gorm:"index"`
	SessionID    string        `gorm:"index"`
	ResourceType string        `gorm:"index"`
	ResourceID   string        `gorm:"index"`
	OldValue     identity.JSON `gorm:"type:json"`
	NewValue     identity.JSON `gorm:"type:json"`
	Risk         string        `gorm:"index"`
	RequestID    string        `gorm:"index"`

	// Geo fields
	GeoCountry string
	GeoRegion  string
	GeoCity    string
	GeoLat     float64
	GeoLong    float64
}

func (gormAuditEvent) TableName() string { return "audit_events" }

type gormAuthToken struct {
	Token      string    `gorm:"primaryKey"`
	TenantID_  string    `gorm:"column:tenant_id;index;not null;default:''"`
	IdentityID string    `gorm:"index"`
	Type       string    `gorm:"index"`
	ExpiresAt  time.Time `gorm:"index"`
}

func (gormAuthToken) TableName() string        { return "auth_tokens" }
func (t *gormAuthToken) TenantID() string      { return t.TenantID_ }
func (t *gormAuthToken) SetTenantID(id string) { t.TenantID_ = id }

func fromCoreAuthToken(t *domain.AuthToken) *gormAuthToken {
	return &gormAuthToken{
		Token:      t.Token,
		IdentityID: t.IdentityID,
		Type:       t.Type,
		ExpiresAt:  t.ExpiresAt,
	}
}

func toCoreAuthToken(t *gormAuthToken) *domain.AuthToken {
	return &domain.AuthToken{
		Token:      t.Token,
		IdentityID: t.IdentityID,
		Type:       t.Type,
		ExpiresAt:  t.ExpiresAt,
	}
}

func fromCoreAuditEvent(e *audit.AuditEvent) *gormAuditEvent {
	if e == nil {
		return nil
	}
	ge := &gormAuditEvent{
		ID:           e.ID,
		Type:         e.Type,
		ActorID:      e.ActorID,
		SubjectID:    e.SubjectID,
		Status:       e.Status,
		Message:      e.Message,
		Metadata:     identity.JSON(e.Metadata),
		CreatedAt:    e.CreatedAt,
		TenantID:     e.TenantID,
		IPAddress:    e.IPAddress,
		UserAgent:    e.UserAgent,
		DeviceID:     e.DeviceID,
		SessionID:    e.SessionID,
		ResourceType: e.ResourceType,
		ResourceID:   e.ResourceID,
		OldValue:     e.OldValue,
		NewValue:     e.NewValue,
		Risk:         string(e.Risk),
		RequestID:    e.RequestID,
	}
	if e.GeoLocation != nil {
		ge.GeoCountry = e.GeoLocation.Country
		ge.GeoRegion = e.GeoLocation.Region
		ge.GeoCity = e.GeoLocation.City
		ge.GeoLat = e.GeoLocation.Latitude
		ge.GeoLong = e.GeoLocation.Longitude
	}
	return ge
}

func toCoreAuditEvent(ge *gormAuditEvent) *audit.AuditEvent {
	if ge == nil {
		return nil
	}
	res := &audit.AuditEvent{
		ID:           ge.ID,
		Type:         ge.Type,
		ActorID:      ge.ActorID,
		SubjectID:    ge.SubjectID,
		Status:       ge.Status,
		Message:      ge.Message,
		Metadata:     ge.Metadata,
		CreatedAt:    ge.CreatedAt,
		TenantID:     ge.TenantID,
		IPAddress:    ge.IPAddress,
		UserAgent:    ge.UserAgent,
		DeviceID:     ge.DeviceID,
		SessionID:    ge.SessionID,
		ResourceType: ge.ResourceType,
		ResourceID:   ge.ResourceID,
		OldValue:     ge.OldValue,
		NewValue:     ge.NewValue,
		Risk:         audit.RiskLevel(ge.Risk),
		RequestID:    ge.RequestID,
	}
	if ge.GeoCountry != "" || ge.GeoCity != "" {
		res.GeoLocation = &audit.GeoLocation{
			Country:   ge.GeoCountry,
			Region:    ge.GeoRegion,
			City:      ge.GeoCity,
			Latitude:  ge.GeoLat,
			Longitude: ge.GeoLong,
		}
	}
	return res
}

type gormIdentity struct {
	ID          string        `gorm:"primaryKey"`
	TenantID_   string        `gorm:"column:tenant_id;index;not null;default:''"`
	Traits      identity.JSON `gorm:"type:json"`
	Roles       identity.JSON `gorm:"type:json"`
	Permissions identity.JSON `gorm:"type:json"`
	CreatedAt   time.Time
	UpdatedAt   time.Time
	DeletedAt   *time.Time `gorm:"index"`
	MFAEnabled  bool
	MFASecret   string
	Verified    bool
	VerifiedAt  *time.Time
	State       string
}

func (gormIdentity) TableName() string        { return "identities" }
func (i *gormIdentity) TenantID() string      { return i.TenantID_ }
func (i *gormIdentity) SetTenantID(id string) { i.TenantID_ = id }

func toCoreIdentity(gi *gormIdentity) *identity.Identity {
	if gi == nil {
		return nil
	}
	return &identity.Identity{
		ID:          gi.ID,
		Traits:      gi.Traits,
		Roles:       gi.Roles,
		Permissions: gi.Permissions,
		CreatedAt:   gi.CreatedAt,
		UpdatedAt:   gi.UpdatedAt,
		DeletedAt:   gi.DeletedAt,
		MFAEnabled:  gi.MFAEnabled,
		MFASecret:   gi.MFASecret,
		Verified:    gi.Verified,
		VerifiedAt:  gi.VerifiedAt,
		State:       gi.State,
	}
}

func fromCoreIdentity(i *identity.Identity) *gormIdentity {
	if i == nil {
		return nil
	}
	return &gormIdentity{
		ID:          i.ID,
		Traits:      i.Traits,
		Roles:       i.Roles,
		Permissions: i.Permissions,
		CreatedAt:   i.CreatedAt,
		UpdatedAt:   i.UpdatedAt,
		DeletedAt:   i.DeletedAt,
		MFAEnabled:  i.MFAEnabled,
		MFASecret:   i.MFASecret,
		Verified:    i.Verified,
		VerifiedAt:  i.VerifiedAt,
		State:       i.State,
	}
}

type gormCredential struct {
	ID         string `gorm:"primaryKey"`
	TenantID_  string `gorm:"column:tenant_id;index;not null;default:''"`
	IdentityID string `gorm:"index"`
	Type       string `gorm:"index"`
	Identifier string `gorm:"index"`
	Secret     string
	Config     identity.JSON `gorm:"type:json"`
	CreatedAt  time.Time
	UpdatedAt  time.Time
}

func (gormCredential) TableName() string        { return "credentials" }
func (c *gormCredential) TenantID() string      { return c.TenantID_ }
func (c *gormCredential) SetTenantID(id string) { c.TenantID_ = id }

func toCoreCredential(gc *gormCredential) *identity.Credential {
	if gc == nil {
		return nil
	}
	return &identity.Credential{
		ID:         gc.ID,
		IdentityID: gc.IdentityID,
		Type:       gc.Type,
		Identifier: gc.Identifier,
		Secret:     gc.Secret,
		Config:     gc.Config,
		CreatedAt:  gc.CreatedAt,
		UpdatedAt:  gc.UpdatedAt,
	}
}

func fromCoreCredential(c *identity.Credential) *gormCredential {
	if c == nil {
		return nil
	}
	return &gormCredential{
		ID:         c.ID,
		IdentityID: c.IdentityID,
		Type:       c.Type,
		Identifier: c.Identifier,
		Secret:     c.Secret,
		Config:     c.Config,
		CreatedAt:  c.CreatedAt,
		UpdatedAt:  c.UpdatedAt,
	}
}

type gormSession struct {
	ID               string `gorm:"primaryKey"`
	TenantID_        string `gorm:"column:tenant_id;index;not null;default:''"`
	IdentityID       string `gorm:"index"`
	RefreshToken     string `gorm:"index"`
	ExpiresAt        time.Time
	RefreshExpiresAt time.Time
	IssuedAt         time.Time
	Active           bool
}

func (gormSession) TableName() string        { return "sessions" }
func (s *gormSession) TenantID() string      { return s.TenantID_ }
func (s *gormSession) SetTenantID(id string) { s.TenantID_ = id }
