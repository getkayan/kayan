package gormstore

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/getkayan/kayan/core/domain"
	"github.com/getkayan/kayan/core/mfa"
	"gorm.io/gorm"
)

// MFARepository persists MFA enrollments, challenges, and recovery codes.
//
// It replaces the in-memory store for production use: MFA enrollments held in
// process memory vanish on restart, which locks every enrolled user out of
// their own account.
type MFARepository struct {
	db    *gorm.DB
	clock domain.Clock
}

var _ mfa.MFAStore = (*MFARepository)(nil)

// MFAOption configures an [MFARepository].
type MFAOption func(*MFARepository)

// WithMFAClock sets the clock used for expiry. Defaults to
// [domain.SystemClock].
func WithMFAClock(c domain.Clock) MFAOption {
	return func(r *MFARepository) { r.clock = c }
}

// NewMFARepository returns a GORM-backed [mfa.MFAStore].
func NewMFARepository(db *gorm.DB, opts ...MFAOption) *MFARepository {
	r := &MFARepository{db: db}
	for _, opt := range opts {
		opt(r)
	}
	r.clock = domain.ClockOrDefault(r.clock)
	return r
}

// AutoMigrate creates the tables this repository needs.
//
// For development only; production deployments should run versioned
// migrations.
func (r *MFARepository) AutoMigrate() error {
	return r.db.AutoMigrate(&gormEnrollment{}, &gormChallenge{}, &gormRecoveryCode{})
}

// --- models ---

type gormEnrollment struct {
	ID         string `gorm:"primaryKey"`
	IdentityID string `gorm:"index"`
	MethodID   string `gorm:"index"`
	Status     string
	Config     []byte `gorm:"type:blob"`
	CreatedAt  time.Time
	TenantId   string `gorm:"column:tenant_id;index"`
}

func (gormEnrollment) TableName() string { return "mfa_enrollments" }

func (e *gormEnrollment) TenantID() string      { return e.TenantId }
func (e *gormEnrollment) SetTenantID(id string) { e.TenantId = id }

type gormChallenge struct {
	ID           string `gorm:"primaryKey"`
	EnrollmentID string `gorm:"index"`
	MethodID     string
	ExpiresAt    time.Time `gorm:"index"`
	Metadata     []byte    `gorm:"type:blob"`
	TenantId     string    `gorm:"column:tenant_id;index"`
}

func (gormChallenge) TableName() string { return "mfa_challenges" }

func (c *gormChallenge) TenantID() string      { return c.TenantId }
func (c *gormChallenge) SetTenantID(id string) { c.TenantId = id }

// gormRecoveryCode stores one hashed recovery code.
//
// The hash arrives already computed by mfa.Manager; this never sees the code
// itself, and must never store one in the clear.
type gormRecoveryCode struct {
	ID         uint   `gorm:"primaryKey;autoIncrement"`
	IdentityID string `gorm:"index"`
	CodeHash   string
	ConsumedAt *time.Time
	CreatedAt  time.Time
	TenantId   string `gorm:"column:tenant_id;index"`
}

func (gormRecoveryCode) TableName() string { return "mfa_recovery_codes" }

func (c *gormRecoveryCode) TenantID() string      { return c.TenantId }
func (c *gormRecoveryCode) SetTenantID(id string) { c.TenantId = id }

// --- enrollments ---

// SaveEnrollment implements [mfa.MFAStore].
func (r *MFARepository) SaveEnrollment(ctx context.Context, enrollment *mfa.Enrollment) error {
	model, err := toGormEnrollment(enrollment)
	if err != nil {
		return err
	}
	return r.db.WithContext(ctx).Create(model).Error
}

// GetEnrollment implements [mfa.MFAStore].
func (r *MFARepository) GetEnrollment(ctx context.Context, id string) (*mfa.Enrollment, error) {
	var model gormEnrollment
	if err := r.db.WithContext(ctx).First(&model, "id = ?", id).Error; err != nil {
		return nil, err
	}
	return fromGormEnrollment(&model)
}

// GetEnrollmentsByIdentity implements [mfa.MFAStore].
func (r *MFARepository) GetEnrollmentsByIdentity(ctx context.Context, identityID string) ([]*mfa.Enrollment, error) {
	var models []gormEnrollment
	if err := r.db.WithContext(ctx).Find(&models, "identity_id = ?", identityID).Error; err != nil {
		return nil, err
	}

	enrollments := make([]*mfa.Enrollment, 0, len(models))
	for i := range models {
		enrollment, err := fromGormEnrollment(&models[i])
		if err != nil {
			return nil, err
		}
		enrollments = append(enrollments, enrollment)
	}
	return enrollments, nil
}

// UpdateEnrollment implements [mfa.MFAStore].
func (r *MFARepository) UpdateEnrollment(ctx context.Context, enrollment *mfa.Enrollment) error {
	model, err := toGormEnrollment(enrollment)
	if err != nil {
		return err
	}

	result := r.db.WithContext(ctx).
		Model(&gormEnrollment{}).
		Where("id = ?", model.ID).
		Updates(map[string]any{
			"status": model.Status,
			"config": model.Config,
		})
	if result.Error != nil {
		return result.Error
	}
	if result.RowsAffected == 0 {
		return gorm.ErrRecordNotFound
	}
	return nil
}

// DeleteEnrollment implements [mfa.MFAStore].
func (r *MFARepository) DeleteEnrollment(ctx context.Context, id string) error {
	return r.db.WithContext(ctx).Delete(&gormEnrollment{}, "id = ?", id).Error
}

// --- challenges ---

// SaveChallenge implements [mfa.MFAStore].
func (r *MFARepository) SaveChallenge(ctx context.Context, challenge *mfa.Challenge) error {
	metadata, err := marshalOptional(challenge.Metadata)
	if err != nil {
		return fmt.Errorf("gormstore: encode challenge metadata: %w", err)
	}

	return r.db.WithContext(ctx).Create(&gormChallenge{
		ID:           challenge.ID,
		EnrollmentID: challenge.EnrollmentID,
		MethodID:     challenge.MethodID,
		ExpiresAt:    challenge.ExpiresAt,
		Metadata:     metadata,
	}).Error
}

// GetChallenge implements [mfa.MFAStore].
//
// An expired challenge is reported as not found. A challenge is a
// single-use authentication step, so serving one past its expiry would let a
// captured challenge be completed later.
func (r *MFARepository) GetChallenge(ctx context.Context, id string) (*mfa.Challenge, error) {
	var model gormChallenge
	err := r.db.WithContext(ctx).
		First(&model, "id = ? AND expires_at > ?", id, r.clock.Now()).Error
	if err != nil {
		return nil, err
	}

	challenge := &mfa.Challenge{
		ID:           model.ID,
		EnrollmentID: model.EnrollmentID,
		MethodID:     model.MethodID,
		ExpiresAt:    model.ExpiresAt,
	}
	if len(model.Metadata) > 0 {
		if err := json.Unmarshal(model.Metadata, &challenge.Metadata); err != nil {
			return nil, fmt.Errorf("gormstore: decode challenge metadata: %w", err)
		}
	}
	return challenge, nil
}

// DeleteChallenge implements [mfa.MFAStore].
func (r *MFARepository) DeleteChallenge(ctx context.Context, id string) error {
	return r.db.WithContext(ctx).Delete(&gormChallenge{}, "id = ?", id).Error
}

// DeleteExpiredChallenges removes challenges past their expiry.
//
// Expired challenges are already unusable; this only stops the table growing.
func (r *MFARepository) DeleteExpiredChallenges(ctx context.Context) (int64, error) {
	result := r.db.WithContext(ctx).Delete(&gormChallenge{}, "expires_at < ?", r.clock.Now())
	return result.RowsAffected, result.Error
}

// --- recovery codes ---

// SaveRecoveryCodes implements [mfa.MFAStore].
//
// It replaces any existing codes for the identity, which is what regenerating
// means: the old set must stop working.
//
// The values are hashes produced by mfa.Manager, never the codes themselves.
func (r *MFARepository) SaveRecoveryCodes(ctx context.Context, identityID string, codes []string) error {
	return r.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if err := tx.Delete(&gormRecoveryCode{}, "identity_id = ?", identityID).Error; err != nil {
			return err
		}
		if len(codes) == 0 {
			return nil
		}

		now := r.clock.Now()
		records := make([]gormRecoveryCode, 0, len(codes))
		for _, hash := range codes {
			records = append(records, gormRecoveryCode{
				IdentityID: identityID,
				CodeHash:   hash,
				CreatedAt:  now,
			})
		}
		return tx.Create(&records).Error
	})
}

// GetRecoveryCodes implements [mfa.MFAStore].
//
// Only unconsumed codes are returned, so a code cannot be redeemed twice.
func (r *MFARepository) GetRecoveryCodes(ctx context.Context, identityID string) ([]string, error) {
	var records []gormRecoveryCode
	err := r.db.WithContext(ctx).
		Find(&records, "identity_id = ? AND consumed_at IS NULL", identityID).Error
	if err != nil {
		return nil, err
	}

	hashes := make([]string, 0, len(records))
	for _, record := range records {
		hashes = append(hashes, record.CodeHash)
	}
	return hashes, nil
}

// ConsumeRecoveryCode implements [mfa.MFAStore].
//
// The code is marked consumed rather than deleted, and the update is
// conditional on it still being unconsumed. Two concurrent redemptions of the
// same code therefore cannot both succeed.
func (r *MFARepository) ConsumeRecoveryCode(ctx context.Context, identityID, codeHash string) error {
	now := r.clock.Now()
	result := r.db.WithContext(ctx).
		Model(&gormRecoveryCode{}).
		Where("identity_id = ? AND code_hash = ? AND consumed_at IS NULL", identityID, codeHash).
		Update("consumed_at", now)
	if result.Error != nil {
		return result.Error
	}
	if result.RowsAffected == 0 {
		// Either the code is unknown or it was consumed first. Both mean the
		// caller must not treat this as a successful authentication.
		return errors.New("gormstore: recovery code is unknown or already consumed")
	}
	return nil
}

// --- conversion ---

func toGormEnrollment(e *mfa.Enrollment) (*gormEnrollment, error) {
	if e == nil {
		return nil, errors.New("gormstore: nil enrollment")
	}

	config, err := marshalOptional(e.Config)
	if err != nil {
		return nil, fmt.Errorf("gormstore: encode enrollment config: %w", err)
	}
	return &gormEnrollment{
		ID:         e.ID,
		IdentityID: e.IdentityID,
		MethodID:   e.MethodID,
		Status:     string(e.Status),
		Config:     config,
		CreatedAt:  e.CreatedAt,
	}, nil
}

func fromGormEnrollment(m *gormEnrollment) (*mfa.Enrollment, error) {
	enrollment := &mfa.Enrollment{
		ID:         m.ID,
		IdentityID: m.IdentityID,
		MethodID:   m.MethodID,
		Status:     mfa.EnrollmentStatus(m.Status),
		CreatedAt:  m.CreatedAt,
	}
	if len(m.Config) > 0 {
		if err := json.Unmarshal(m.Config, &enrollment.Config); err != nil {
			return nil, fmt.Errorf("gormstore: decode enrollment config: %w", err)
		}
	}
	return enrollment, nil
}

// marshalOptional encodes a value, returning nil for an absent one so the
// column stays NULL rather than holding the four bytes "null".
func marshalOptional(value any) ([]byte, error) {
	if value == nil {
		return nil, nil
	}
	return json.Marshal(value)
}
