package gormstore

import (
	"context"
	"errors"
	"time"

	"github.com/getkayan/kayan/kayan-oidc-provider/oauth2"
	"gorm.io/gorm"
)

// Compile-time proof that this repository serves the device grant.
var _ oauth2.DeviceAuthorizationStore = (*OAuth2Repository)(nil)

// gormDeviceAuthorization is the stored form of an oauth2.DeviceAuthorization.
//
// Every state change below is a single guarded UPDATE or DELETE whose WHERE
// clause restates the precondition, so two replicas racing on one record
// cannot both win: RowsAffected says which one did.
type gormDeviceAuthorization struct {
	DeviceCode string `gorm:"primaryKey"`

	// Unique across rows: two live authorizations sharing a code would let
	// one user's approval reach another's device. Expired rows holding a code
	// are cleared before a save reuses it.
	UserCode string `gorm:"uniqueIndex"`

	ClientID  string    `gorm:"index"`
	TenantID  string    `gorm:"index"`
	Scopes    []string  `gorm:"type:text;serializer:json"`
	ExpiresAt time.Time `gorm:"index"`
	// poll_interval, because INTERVAL is a reserved word in PostgreSQL and
	// MySQL.
	Interval     time.Duration `gorm:"column:poll_interval"`
	LastPolledAt time.Time
	Status       string

	VerificationHandle string `gorm:"index"`
	VerifiedBy         string

	IdentityID string
	AuthNonce  string
	AuthTime   time.Time
	AuthACR    string
	AuthAMR    []string `gorm:"type:text;serializer:json"`
}

func (gormDeviceAuthorization) TableName() string { return "oauth2_device_authorizations" }

func fromCoreDevice(a *oauth2.DeviceAuthorization) *gormDeviceAuthorization {
	return &gormDeviceAuthorization{
		DeviceCode:         a.DeviceCode,
		UserCode:           a.UserCode,
		ClientID:           a.ClientID,
		TenantID:           a.TenantID,
		Scopes:             a.Scopes,
		ExpiresAt:          a.ExpiresAt,
		Interval:           a.Interval,
		LastPolledAt:       a.LastPolledAt,
		Status:             string(a.Status),
		VerificationHandle: a.VerificationHandle,
		VerifiedBy:         a.VerifiedBy,
		IdentityID:         a.IdentityID,
		AuthNonce:          a.Authentication.Nonce,
		AuthTime:           a.Authentication.AuthTime,
		AuthACR:            a.Authentication.ACR,
		AuthAMR:            a.Authentication.AMR,
	}
}

func toCoreDevice(g *gormDeviceAuthorization) *oauth2.DeviceAuthorization {
	return &oauth2.DeviceAuthorization{
		DeviceCode:         g.DeviceCode,
		UserCode:           g.UserCode,
		ClientID:           g.ClientID,
		TenantID:           g.TenantID,
		Scopes:             g.Scopes,
		ExpiresAt:          g.ExpiresAt,
		Interval:           g.Interval,
		LastPolledAt:       g.LastPolledAt,
		Status:             oauth2.DeviceAuthorizationStatus(g.Status),
		VerificationHandle: g.VerificationHandle,
		VerifiedBy:         g.VerifiedBy,
		IdentityID:         g.IdentityID,
		Authentication: oauth2.AuthenticationInfo{
			Nonce:    g.AuthNonce,
			AuthTime: g.AuthTime,
			ACR:      g.AuthACR,
			AMR:      g.AuthAMR,
		},
	}
}

// SaveDeviceAuthorization implements [oauth2.DeviceAuthorizationStore].
func (r *OAuth2Repository) SaveDeviceAuthorization(ctx context.Context, a *oauth2.DeviceAuthorization, now time.Time) error {
	db := r.db.WithContext(ctx)

	// An expired authorization must not hold its code hostage.
	if err := db.Where("user_code = ? AND expires_at <= ?", a.UserCode, now).
		Delete(&gormDeviceAuthorization{}).Error; err != nil {
		return err
	}

	if err := db.Create(fromCoreDevice(a)).Error; err != nil {
		// The unique index is what makes the collision check atomic. Drivers
		// report its violation differently, so it is recognised by looking
		// rather than by parsing the error.
		var count int64
		if lookErr := db.Model(&gormDeviceAuthorization{}).
			Where("user_code = ?", a.UserCode).Count(&count).Error; lookErr == nil && count > 0 {
			return oauth2.ErrUserCodeCollision
		}
		return err
	}
	return nil
}

// BeginDeviceVerification implements [oauth2.DeviceAuthorizationStore].
func (r *OAuth2Repository) BeginDeviceVerification(ctx context.Context, userCode, tenantID, handle, identityID string, now time.Time) (*oauth2.DeviceAuthorization, error) {
	db := r.db.WithContext(ctx)
	res := db.Model(&gormDeviceAuthorization{}).
		Where("user_code = ? AND tenant_id = ? AND status = ? AND expires_at > ?",
			userCode, tenantID, string(oauth2.DeviceAuthorizationPending), now).
		Updates(map[string]any{"verification_handle": handle, "verified_by": identityID})
	if res.Error != nil {
		return nil, res.Error
	}
	if res.RowsAffected == 0 {
		return nil, oauth2.ErrDeviceAuthorizationNotFound
	}

	var row gormDeviceAuthorization
	if err := db.Where("verification_handle = ?", handle).First(&row).Error; err != nil {
		return nil, oauth2.ErrDeviceAuthorizationNotFound
	}
	return toCoreDevice(&row), nil
}

// CompleteDeviceAuthorization implements [oauth2.DeviceAuthorizationStore].
func (r *OAuth2Repository) CompleteDeviceAuthorization(ctx context.Context, handle, identityID string, status oauth2.DeviceAuthorizationStatus, auth oauth2.AuthenticationInfo, now time.Time) error {
	if handle == "" {
		return oauth2.ErrDeviceAuthorizationNotFound
	}
	res := r.db.WithContext(ctx).Model(&gormDeviceAuthorization{}).
		Where("verification_handle = ? AND verified_by = ? AND status = ? AND expires_at > ?",
			handle, identityID, string(oauth2.DeviceAuthorizationPending), now).
		// Select names every column so the empty handle is written: Updates
		// with a struct skips zero values, and a map would bypass the JSON
		// serializer on AuthAMR.
		Select("status", "identity_id", "auth_nonce", "auth_time", "auth_acr", "auth_amr", "verification_handle").
		Updates(&gormDeviceAuthorization{
			Status:             string(status),
			IdentityID:         identityID,
			AuthNonce:          auth.Nonce,
			AuthTime:           auth.AuthTime,
			AuthACR:            auth.ACR,
			AuthAMR:            auth.AMR,
			VerificationHandle: "",
		})
	if res.Error != nil {
		return res.Error
	}
	if res.RowsAffected == 0 {
		return oauth2.ErrDeviceAuthorizationNotFound
	}
	return nil
}

// PollDeviceAuthorization implements [oauth2.DeviceAuthorizationStore].
//
// The update is a compare-and-set on the polling state read: a concurrent
// poll that changed it first means this one arrived inside the interval, and
// it is answered slow_down.
func (r *OAuth2Repository) PollDeviceAuthorization(ctx context.Context, deviceCode, clientID string, now time.Time) (*oauth2.DeviceAuthorization, bool, error) {
	db := r.db.WithContext(ctx)

	var row gormDeviceAuthorization
	err := db.Where("device_code = ? AND client_id = ?", deviceCode, clientID).First(&row).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, false, oauth2.ErrDeviceAuthorizationNotFound
	}
	if err != nil {
		return nil, false, err
	}
	before := toCoreDevice(&row)

	slowDown := !row.LastPolledAt.IsZero() && now.Before(row.LastPolledAt.Add(row.Interval))
	interval := row.Interval
	if slowDown {
		interval += oauth2.DeviceSlowDownIncrement
	}

	res := db.Model(&gormDeviceAuthorization{}).
		Where("device_code = ? AND client_id = ? AND last_polled_at = ? AND poll_interval = ?",
			deviceCode, clientID, row.LastPolledAt, row.Interval).
		Updates(map[string]any{"last_polled_at": now, "poll_interval": interval})
	if res.Error != nil {
		return nil, false, res.Error
	}
	if res.RowsAffected == 0 {
		return before, true, nil
	}
	return before, slowDown, nil
}

// ConsumeDeviceAuthorization implements [oauth2.DeviceAuthorizationStore].
func (r *OAuth2Repository) ConsumeDeviceAuthorization(ctx context.Context, deviceCode, clientID string, now time.Time) (*oauth2.DeviceAuthorization, error) {
	db := r.db.WithContext(ctx)
	approved := string(oauth2.DeviceAuthorizationApproved)

	var row gormDeviceAuthorization
	err := db.Where("device_code = ? AND client_id = ? AND status = ? AND expires_at > ?",
		deviceCode, clientID, approved, now).First(&row).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, oauth2.ErrDeviceAuthorizationNotFound
	}
	if err != nil {
		return nil, err
	}

	// The delete restates the read's conditions; only one of two concurrent
	// redemptions removes the row.
	res := db.Where("device_code = ? AND client_id = ? AND status = ?", deviceCode, clientID, approved).
		Delete(&gormDeviceAuthorization{})
	if res.Error != nil {
		return nil, res.Error
	}
	if res.RowsAffected == 0 {
		return nil, oauth2.ErrDeviceAuthorizationNotFound
	}
	return toCoreDevice(&row), nil
}

// DeleteExpiredDeviceAuthorizations implements [oauth2.DeviceAuthorizationStore].
func (r *OAuth2Repository) DeleteExpiredDeviceAuthorizations(ctx context.Context, now time.Time) error {
	return r.db.WithContext(ctx).Where("expires_at <= ?", now).Delete(&gormDeviceAuthorization{}).Error
}
