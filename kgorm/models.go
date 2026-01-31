package kgorm

import (
	"time"

	"github.com/getkayan/kayan/core/audit"
	"github.com/getkayan/kayan/core/domain"
	"github.com/getkayan/kayan/core/identity"
	"github.com/getkayan/kayan/core/oauth2"
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
}

func (gormAuditEvent) TableName() string { return "audit_events" }

type gormAuthToken struct {
	Token      string    `gorm:"primaryKey"`
	IdentityID string    `gorm:"index"`
	Type       string    `gorm:"index"`
	ExpiresAt  time.Time `gorm:"index"`
}

func (gormAuthToken) TableName() string { return "auth_tokens" }

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
	return &gormAuditEvent{
		ID:        e.ID,
		Type:      e.Type,
		ActorID:   e.ActorID,
		SubjectID: e.SubjectID,
		Status:    e.Status,
		Message:   e.Message,
		Metadata:  identity.JSON(e.Metadata),
		CreatedAt: e.CreatedAt,
	}
}

type gormIdentity struct {
	ID          string        `gorm:"primaryKey"`
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
}

func (gormIdentity) TableName() string { return "identities" }

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
	}
}

type gormCredential struct {
	ID         string `gorm:"primaryKey"`
	IdentityID string `gorm:"index"`
	Type       string `gorm:"index"`
	Identifier string `gorm:"index"`
	Secret     string
	Config     identity.JSON `gorm:"type:json"`
	CreatedAt  time.Time
	UpdatedAt  time.Time
}

func (gormCredential) TableName() string { return "credentials" }

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
	IdentityID       string `gorm:"index"`
	RefreshToken     string `gorm:"index"`
	ExpiresAt        time.Time
	RefreshExpiresAt time.Time
	IssuedAt         time.Time
	Active           bool
}

func (gormSession) TableName() string { return "sessions" }

type gormClient struct {
	ID                   string `gorm:"primaryKey"`
	Secret               string
	RedirectURIs         []string `gorm:"type:text;serializer:json"`
	GrantTypes           []string `gorm:"type:text;serializer:json"`
	Scopes               []string `gorm:"type:text;serializer:json"`
	AppName              string
	BackChannelLogoutURI string
}

func (gormClient) TableName() string { return "oauth2_clients" }

func toCoreClient(gc *gormClient) *oauth2.Client {
	if gc == nil {
		return nil
	}
	return &oauth2.Client{
		ID:                   gc.ID,
		Secret:               gc.Secret,
		RedirectURIs:         gc.RedirectURIs,
		GrantTypes:           gc.GrantTypes,
		Scopes:               gc.Scopes,
		AppName:              gc.AppName,
		BackChannelLogoutURI: gc.BackChannelLogoutURI,
	}
}

func fromCoreClient(c *oauth2.Client) *gormClient {
	if c == nil {
		return nil
	}
	return &gormClient{
		ID:                   c.ID,
		Secret:               c.Secret,
		RedirectURIs:         c.RedirectURIs,
		GrantTypes:           c.GrantTypes,
		Scopes:               c.Scopes,
		AppName:              c.AppName,
		BackChannelLogoutURI: c.BackChannelLogoutURI,
	}
}

type gormAuthCode struct {
	Code                string `gorm:"primaryKey"`
	ClientID            string `gorm:"index"`
	IdentityID          string `gorm:"index"`
	RedirectURI         string
	Scopes              []string `gorm:"type:text;serializer:json"`
	CodeChallenge       string
	CodeChallengeMethod string
	ExpiresAt           time.Time `gorm:"index"`
}

func (gormAuthCode) TableName() string { return "oauth2_auth_codes" }

func toCoreAuthCode(gc *gormAuthCode) *oauth2.AuthCode {
	if gc == nil {
		return nil
	}
	return &oauth2.AuthCode{
		Code:                gc.Code,
		ClientID:            gc.ClientID,
		IdentityID:          gc.IdentityID,
		RedirectURI:         gc.RedirectURI,
		Scopes:              gc.Scopes,
		CodeChallenge:       gc.CodeChallenge,
		CodeChallengeMethod: gc.CodeChallengeMethod,
		ExpiresAt:           gc.ExpiresAt,
	}
}

func fromCoreAuthCode(c *oauth2.AuthCode) *gormAuthCode {
	if c == nil {
		return nil
	}
	return &gormAuthCode{
		Code:                c.Code,
		ClientID:            c.ClientID,
		IdentityID:          c.IdentityID,
		RedirectURI:         c.RedirectURI,
		Scopes:              c.Scopes,
		CodeChallenge:       c.CodeChallenge,
		CodeChallengeMethod: c.CodeChallengeMethod,
		ExpiresAt:           c.ExpiresAt,
	}
}

type gormRefreshToken struct {
	Token      string    `gorm:"primaryKey"`
	ClientID   string    `gorm:"index"`
	IdentityID string    `gorm:"index"`
	Scopes     []string  `gorm:"type:text;serializer:json"`
	ExpiresAt  time.Time `gorm:"index"`
}

func (gormRefreshToken) TableName() string { return "oauth2_refresh_tokens" }

func toCoreRefreshToken(gr *gormRefreshToken) *oauth2.RefreshToken {
	if gr == nil {
		return nil
	}
	return &oauth2.RefreshToken{
		Token:      gr.Token,
		ClientID:   gr.ClientID,
		IdentityID: gr.IdentityID,
		Scopes:     gr.Scopes,
		ExpiresAt:  gr.ExpiresAt,
	}
}

func fromCoreRefreshToken(r *oauth2.RefreshToken) *gormRefreshToken {
	if r == nil {
		return nil
	}
	return &gormRefreshToken{
		Token:      r.Token,
		ClientID:   r.ClientID,
		IdentityID: r.IdentityID,
		Scopes:     r.Scopes,
		ExpiresAt:  r.ExpiresAt,
	}
}
