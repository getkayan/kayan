// Package device provides device trust and fingerprinting for Kayan IAM.
//
// This package enables tracking, evaluating, and managing devices used to
// authenticate identities. By recording device fingerprints and trust levels,
// applications can detect new/unknown devices and require additional verification
// (e.g., step-up authentication or MFA).
//
// # Architecture
//
// The device package is standalone with zero internal dependencies (stdlib only),
// following the same pattern as core/rbac and core/rebac.
//
// # Trust Levels
//
//   - Unknown: First-time device, identity unknown
//   - Low: Recently registered, not yet verified
//   - Medium: Default trust for verified devices
//   - High: Long-standing, frequently used, verified device
//   - Blocked: Explicitly blocked device
//
// # Usage
//
//	store := device.NewMemoryStore()
//	manager := device.NewManager(store)
//
//	// Register a device
//	dev, _ := manager.Register(ctx, "user-123", device.DeviceInfo{
//	    Fingerprint: "abc123hash",
//	    UserAgent:   "Mozilla/5.0...",
//	    IPAddress:   "192.168.1.1",
//	})
//
//	// Evaluate trust on login
//	result, _ := manager.Evaluate(ctx, "user-123", device.DeviceInfo{
//	    Fingerprint: "abc123hash",
//	})
//	if result.RequiresMFA {
//	    // Prompt for additional verification
//	}
package device

import (
	"time"
)

// TrustLevel represents the trust classification of a device.
type TrustLevel string

const (
	// TrustUnknown indicates a first-time device with no history.
	TrustUnknown TrustLevel = "unknown"
	// TrustLow indicates a recently registered, unverified device.
	TrustLow TrustLevel = "low"
	// TrustMedium indicates a verified device with normal trust.
	TrustMedium TrustLevel = "medium"
	// TrustHigh indicates a long-standing, frequently used, verified device.
	TrustHigh TrustLevel = "high"
	// TrustBlocked indicates an explicitly blocked device.
	TrustBlocked TrustLevel = "blocked"
)

// Device represents a registered device associated with an identity.
type Device struct {
	ID          string     `json:"id"`
	IdentityID  string     `json:"identity_id"`
	Name        string     `json:"name,omitempty"`        // User-assigned name (e.g., "Work Laptop")
	Fingerprint string     `json:"fingerprint"`           // Browser/device fingerprint hash
	UserAgent   string     `json:"user_agent,omitempty"`
	IPAddress   string     `json:"ip_address,omitempty"`
	TrustLevel  TrustLevel `json:"trust_level"`
	LastSeenAt  time.Time  `json:"last_seen_at"`
	CreatedAt   time.Time  `json:"created_at"`
	Verified    bool       `json:"verified"` // User confirmed this device
}

// DeviceInfo contains the information provided when registering or evaluating a device.
type DeviceInfo struct {
	Fingerprint string `json:"fingerprint"`
	UserAgent   string `json:"user_agent,omitempty"`
	IPAddress   string `json:"ip_address,omitempty"`
	Name        string `json:"name,omitempty"`
}

// EvaluationResult contains the outcome of evaluating a device against known devices.
type EvaluationResult struct {
	Device      *Device    `json:"device,omitempty"`
	TrustLevel  TrustLevel `json:"trust_level"`
	IsNewDevice bool       `json:"is_new_device"`
	RequiresMFA bool       `json:"requires_mfa"` // Recommendation based on trust policy
}
