package device

import (
	"context"
)

// Store defines the interface for persisting and querying devices.
// Implementations may use any backend (SQL, Redis, in-memory, etc.).
type Store interface {
	// SaveDevice persists a new device record.
	SaveDevice(ctx context.Context, device *Device) error

	// GetDevice retrieves a device by its ID.
	GetDevice(ctx context.Context, id string) (*Device, error)

	// GetDeviceByFingerprint retrieves a device by identity ID and fingerprint.
	GetDeviceByFingerprint(ctx context.Context, identityID, fingerprint string) (*Device, error)

	// GetDevicesByIdentity returns all devices registered to an identity.
	GetDevicesByIdentity(ctx context.Context, identityID string) ([]*Device, error)

	// UpdateDevice updates an existing device record.
	UpdateDevice(ctx context.Context, device *Device) error

	// DeleteDevice removes a device by its ID.
	DeleteDevice(ctx context.Context, id string) error

	// DeleteDevicesByIdentity removes all devices for an identity.
	DeleteDevicesByIdentity(ctx context.Context, identityID string) error
}
