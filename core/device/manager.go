package device

import (
	"context"
	"crypto/sha256"
	"fmt"
	"time"
)

// Manager provides a high-level API for device trust operations.
// It wraps the Store to provide device registration, trust evaluation,
// and lifecycle management.
//
// Usage:
//
//	store := device.NewMemoryStore()
//	manager := device.NewManager(store, device.WithMaxDevices(10))
//
//	// Register a device after successful login
//	dev, _ := manager.Register(ctx, "user-123", device.DeviceInfo{
//	    Fingerprint: "browser-fp-hash",
//	    UserAgent:   "Mozilla/5.0...",
//	    IPAddress:   "10.0.0.1",
//	})
//
//	// Evaluate trust on next login
//	result, _ := manager.Evaluate(ctx, "user-123", device.DeviceInfo{
//	    Fingerprint: "browser-fp-hash",
//	})
type Manager struct {
	store          Store
	maxDevices     int
	autoTrustAfter time.Duration
}

// ManagerOption configures a Manager.
type ManagerOption func(*Manager)

// WithMaxDevices sets the maximum number of devices per identity.
// When the limit is reached, registering a new device returns an error.
// Default is 0 (unlimited).
func WithMaxDevices(n int) ManagerOption {
	return func(m *Manager) { m.maxDevices = n }
}

// WithAutoTrustAfter sets the duration after which a verified device
// automatically upgrades to TrustHigh. Default is 0 (no auto-upgrade).
func WithAutoTrustAfter(d time.Duration) ManagerOption {
	return func(m *Manager) { m.autoTrustAfter = d }
}

// NewManager creates a new device trust manager.
func NewManager(store Store, opts ...ManagerOption) *Manager {
	m := &Manager{
		store: store,
	}
	for _, opt := range opts {
		opt(m)
	}
	return m
}

// Register records a new device for an identity. If the device fingerprint
// is already registered, it updates the last seen timestamp and returns
// the existing device.
func (m *Manager) Register(ctx context.Context, identityID string, info DeviceInfo) (*Device, error) {
	if info.Fingerprint == "" {
		return nil, fmt.Errorf("device: fingerprint is required")
	}

	// Check if device already exists
	existing, err := m.store.GetDeviceByFingerprint(ctx, identityID, info.Fingerprint)
	if err == nil && existing != nil {
		// Update last seen
		existing.LastSeenAt = time.Now()
		if info.IPAddress != "" {
			existing.IPAddress = info.IPAddress
		}
		if info.UserAgent != "" {
			existing.UserAgent = info.UserAgent
		}
		if err := m.store.UpdateDevice(ctx, existing); err != nil {
			return nil, fmt.Errorf("device: failed to update: %w", err)
		}
		return existing, nil
	}

	// Check max devices limit
	if m.maxDevices > 0 {
		devices, err := m.store.GetDevicesByIdentity(ctx, identityID)
		if err != nil {
			return nil, fmt.Errorf("device: failed to list devices: %w", err)
		}
		if len(devices) >= m.maxDevices {
			return nil, fmt.Errorf("device: maximum device limit (%d) reached", m.maxDevices)
		}
	}

	// Create new device
	now := time.Now()
	device := &Device{
		ID:          m.generateID(identityID, info.Fingerprint),
		IdentityID:  identityID,
		Name:        info.Name,
		Fingerprint: info.Fingerprint,
		UserAgent:   info.UserAgent,
		IPAddress:   info.IPAddress,
		TrustLevel:  TrustLow,
		LastSeenAt:  now,
		CreatedAt:   now,
		Verified:    false,
	}

	if err := m.store.SaveDevice(ctx, device); err != nil {
		return nil, fmt.Errorf("device: failed to save: %w", err)
	}

	return device, nil
}

// Verify marks a device as verified and upgrades its trust level to Medium.
func (m *Manager) Verify(ctx context.Context, deviceID string) error {
	device, err := m.store.GetDevice(ctx, deviceID)
	if err != nil {
		return fmt.Errorf("device: %w", err)
	}

	if device.TrustLevel == TrustBlocked {
		return fmt.Errorf("device: cannot verify a blocked device")
	}

	device.Verified = true
	device.TrustLevel = TrustMedium

	return m.store.UpdateDevice(ctx, device)
}

// Evaluate assesses the trust level of a device for a given identity.
// Returns an EvaluationResult with the trust level and whether MFA is recommended.
func (m *Manager) Evaluate(ctx context.Context, identityID string, info DeviceInfo) (*EvaluationResult, error) {
	if info.Fingerprint == "" {
		return &EvaluationResult{
			TrustLevel:  TrustUnknown,
			IsNewDevice: true,
			RequiresMFA: true,
		}, nil
	}

	device, err := m.store.GetDeviceByFingerprint(ctx, identityID, info.Fingerprint)
	if err != nil || device == nil {
		// Unknown device
		return &EvaluationResult{
			TrustLevel:  TrustUnknown,
			IsNewDevice: true,
			RequiresMFA: true,
		}, nil
	}

	// Blocked device
	if device.TrustLevel == TrustBlocked {
		return &EvaluationResult{
			Device:      device,
			TrustLevel:  TrustBlocked,
			IsNewDevice: false,
			RequiresMFA: true,
		}, nil
	}

	// Auto-upgrade to high trust if eligible
	if m.autoTrustAfter > 0 && device.Verified && device.TrustLevel == TrustMedium {
		if time.Since(device.CreatedAt) > m.autoTrustAfter {
			device.TrustLevel = TrustHigh
			m.store.UpdateDevice(ctx, device)
		}
	}

	// Update last seen
	device.LastSeenAt = time.Now()
	if info.IPAddress != "" {
		device.IPAddress = info.IPAddress
	}
	m.store.UpdateDevice(ctx, device)

	// Determine MFA requirement
	requiresMFA := device.TrustLevel == TrustLow || device.TrustLevel == TrustUnknown

	return &EvaluationResult{
		Device:      device,
		TrustLevel:  device.TrustLevel,
		IsNewDevice: false,
		RequiresMFA: requiresMFA,
	}, nil
}

// Block marks a device as blocked, preventing it from being trusted.
func (m *Manager) Block(ctx context.Context, deviceID string) error {
	device, err := m.store.GetDevice(ctx, deviceID)
	if err != nil {
		return fmt.Errorf("device: %w", err)
	}

	device.TrustLevel = TrustBlocked
	device.Verified = false

	return m.store.UpdateDevice(ctx, device)
}

// ListDevices returns all devices registered to an identity.
func (m *Manager) ListDevices(ctx context.Context, identityID string) ([]*Device, error) {
	return m.store.GetDevicesByIdentity(ctx, identityID)
}

// RevokeAll removes all devices for an identity.
func (m *Manager) RevokeAll(ctx context.Context, identityID string) error {
	return m.store.DeleteDevicesByIdentity(ctx, identityID)
}

// generateID creates a deterministic device ID from identity and fingerprint.
func (m *Manager) generateID(identityID, fingerprint string) string {
	h := sha256.Sum256([]byte(identityID + ":" + fingerprint))
	return fmt.Sprintf("%x", h[:16])
}
