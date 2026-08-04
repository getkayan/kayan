package gormstore

import (
	"context"
	"errors"
	"time"

	"github.com/getkayan/kayan/core/device"
	"gorm.io/gorm"
)

// DeviceRepository persists device trust records.
//
// It replaces the in-memory store for production use: device trust held in
// process memory is lost on restart, so every returning user is treated as
// arriving on a new device and challenged again.
type DeviceRepository struct {
	db *gorm.DB
}

var _ device.Store = (*DeviceRepository)(nil)

// NewDeviceRepository returns a GORM-backed [device.Store].
func NewDeviceRepository(db *gorm.DB) *DeviceRepository {
	return &DeviceRepository{db: db}
}

// AutoMigrate creates the tables this repository needs.
//
// For development only; production deployments should run versioned
// migrations.
func (r *DeviceRepository) AutoMigrate() error {
	return r.db.AutoMigrate(&gormDevice{})
}

type gormDevice struct {
	ID         string `gorm:"primaryKey"`
	IdentityID string `gorm:"index:idx_device_identity_fingerprint"`
	Name       string
	// Fingerprint is supplied by the client and is therefore spoofable. It
	// identifies a device; it does not authenticate one.
	Fingerprint string `gorm:"index:idx_device_identity_fingerprint"`
	UserAgent   string
	IPAddress   string
	TrustLevel  string
	LastSeenAt  time.Time
	CreatedAt   time.Time
	Verified    bool
	TenantId    string `gorm:"column:tenant_id;index"`
}

func (gormDevice) TableName() string { return "devices" }

func (d *gormDevice) TenantID() string      { return d.TenantId }
func (d *gormDevice) SetTenantID(id string) { d.TenantId = id }

// SaveDevice implements [device.Store].
func (r *DeviceRepository) SaveDevice(ctx context.Context, d *device.Device) error {
	if d == nil {
		return errors.New("gormstore: nil device")
	}
	return r.db.WithContext(ctx).Create(toGormDevice(d)).Error
}

// GetDevice implements [device.Store].
func (r *DeviceRepository) GetDevice(ctx context.Context, id string) (*device.Device, error) {
	var model gormDevice
	if err := r.db.WithContext(ctx).First(&model, "id = ?", id).Error; err != nil {
		return nil, err
	}
	return fromGormDevice(&model), nil
}

// GetDeviceByFingerprint implements [device.Store].
func (r *DeviceRepository) GetDeviceByFingerprint(ctx context.Context, identityID, fingerprint string) (*device.Device, error) {
	var model gormDevice
	err := r.db.WithContext(ctx).
		First(&model, "identity_id = ? AND fingerprint = ?", identityID, fingerprint).Error
	if err != nil {
		return nil, err
	}
	return fromGormDevice(&model), nil
}

// GetDevicesByIdentity implements [device.Store].
func (r *DeviceRepository) GetDevicesByIdentity(ctx context.Context, identityID string) ([]*device.Device, error) {
	var models []gormDevice
	if err := r.db.WithContext(ctx).Find(&models, "identity_id = ?", identityID).Error; err != nil {
		return nil, err
	}

	devices := make([]*device.Device, 0, len(models))
	for i := range models {
		devices = append(devices, fromGormDevice(&models[i]))
	}
	return devices, nil
}

// UpdateDevice implements [device.Store].
func (r *DeviceRepository) UpdateDevice(ctx context.Context, d *device.Device) error {
	if d == nil {
		return errors.New("gormstore: nil device")
	}

	result := r.db.WithContext(ctx).
		Model(&gormDevice{}).
		Where("id = ?", d.ID).
		Updates(map[string]any{
			"name":         d.Name,
			"user_agent":   d.UserAgent,
			"ip_address":   d.IPAddress,
			"trust_level":  string(d.TrustLevel),
			"last_seen_at": d.LastSeenAt,
			"verified":     d.Verified,
		})
	if result.Error != nil {
		return result.Error
	}
	if result.RowsAffected == 0 {
		return gorm.ErrRecordNotFound
	}
	return nil
}

// DeleteDevice implements [device.Store].
func (r *DeviceRepository) DeleteDevice(ctx context.Context, id string) error {
	return r.db.WithContext(ctx).Delete(&gormDevice{}, "id = ?", id).Error
}

// DeleteDevicesByIdentity implements [device.Store].
//
// This is what "sign out everywhere" and "forget my devices" run, so it must
// remove every record rather than only the current one.
func (r *DeviceRepository) DeleteDevicesByIdentity(ctx context.Context, identityID string) error {
	return r.db.WithContext(ctx).Delete(&gormDevice{}, "identity_id = ?", identityID).Error
}

func toGormDevice(d *device.Device) *gormDevice {
	return &gormDevice{
		ID:          d.ID,
		IdentityID:  d.IdentityID,
		Name:        d.Name,
		Fingerprint: d.Fingerprint,
		UserAgent:   d.UserAgent,
		IPAddress:   d.IPAddress,
		TrustLevel:  string(d.TrustLevel),
		LastSeenAt:  d.LastSeenAt,
		CreatedAt:   d.CreatedAt,
		Verified:    d.Verified,
	}
}

func fromGormDevice(m *gormDevice) *device.Device {
	return &device.Device{
		ID:          m.ID,
		IdentityID:  m.IdentityID,
		Name:        m.Name,
		Fingerprint: m.Fingerprint,
		UserAgent:   m.UserAgent,
		IPAddress:   m.IPAddress,
		TrustLevel:  device.TrustLevel(m.TrustLevel),
		LastSeenAt:  m.LastSeenAt,
		CreatedAt:   m.CreatedAt,
		Verified:    m.Verified,
	}
}
