package device

import (
	"context"
	"testing"
	"time"
)

func TestManager_Register(t *testing.T) {
	tests := []struct {
		name    string
		info    DeviceInfo
		wantErr bool
	}{
		{
			name: "register new device",
			info: DeviceInfo{
				Fingerprint: "fp-abc123",
				UserAgent:   "Mozilla/5.0",
				IPAddress:   "10.0.0.1",
				Name:        "Work Laptop",
			},
		},
		{
			name:    "empty fingerprint",
			info:    DeviceInfo{},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			store := NewMemoryStore()
			mgr := NewManager(store)

			dev, err := mgr.Register(context.Background(), "user-1", tt.info)
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if dev.IdentityID != "user-1" {
				t.Errorf("expected identity_id 'user-1', got %q", dev.IdentityID)
			}
			if dev.TrustLevel != TrustLow {
				t.Errorf("expected trust level %q, got %q", TrustLow, dev.TrustLevel)
			}
			if dev.Verified {
				t.Error("new device should not be verified")
			}
		})
	}
}

func TestManager_Register_DuplicateFingerprint(t *testing.T) {
	store := NewMemoryStore()
	mgr := NewManager(store)
	ctx := context.Background()

	info := DeviceInfo{Fingerprint: "fp-dup", UserAgent: "UA1", IPAddress: "10.0.0.1"}

	// First registration
	dev1, err := mgr.Register(ctx, "user-1", info)
	if err != nil {
		t.Fatalf("first registration failed: %v", err)
	}

	// Second registration with same fingerprint — should update, not create new
	info.IPAddress = "10.0.0.2"
	dev2, err := mgr.Register(ctx, "user-1", info)
	if err != nil {
		t.Fatalf("second registration failed: %v", err)
	}

	if dev1.ID != dev2.ID {
		t.Error("expected same device ID for duplicate fingerprint")
	}
	if dev2.IPAddress != "10.0.0.2" {
		t.Errorf("expected updated IP '10.0.0.2', got %q", dev2.IPAddress)
	}
}

func TestManager_MaxDevices(t *testing.T) {
	store := NewMemoryStore()
	mgr := NewManager(store, WithMaxDevices(2))
	ctx := context.Background()

	_, err := mgr.Register(ctx, "user-1", DeviceInfo{Fingerprint: "fp-1"})
	if err != nil {
		t.Fatalf("device 1 failed: %v", err)
	}

	_, err = mgr.Register(ctx, "user-1", DeviceInfo{Fingerprint: "fp-2"})
	if err != nil {
		t.Fatalf("device 2 failed: %v", err)
	}

	_, err = mgr.Register(ctx, "user-1", DeviceInfo{Fingerprint: "fp-3"})
	if err == nil {
		t.Fatal("expected error for exceeding max devices")
	}
}

func TestManager_Evaluate(t *testing.T) {
	store := NewMemoryStore()
	mgr := NewManager(store)
	ctx := context.Background()

	// Evaluate unknown device
	result, err := mgr.Evaluate(ctx, "user-1", DeviceInfo{Fingerprint: "fp-unknown"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.IsNewDevice {
		t.Error("expected IsNewDevice=true for unknown device")
	}
	if result.TrustLevel != TrustUnknown {
		t.Errorf("expected TrustUnknown, got %q", result.TrustLevel)
	}
	if !result.RequiresMFA {
		t.Error("expected RequiresMFA=true for unknown device")
	}

	// Register and verify a device
	dev, _ := mgr.Register(ctx, "user-1", DeviceInfo{Fingerprint: "fp-known"})
	mgr.Verify(ctx, dev.ID)

	// Evaluate known, verified device
	result, err = mgr.Evaluate(ctx, "user-1", DeviceInfo{Fingerprint: "fp-known"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.IsNewDevice {
		t.Error("expected IsNewDevice=false for known device")
	}
	if result.TrustLevel != TrustMedium {
		t.Errorf("expected TrustMedium, got %q", result.TrustLevel)
	}
	if result.RequiresMFA {
		t.Error("expected RequiresMFA=false for verified device")
	}
}

func TestManager_Evaluate_EmptyFingerprint(t *testing.T) {
	store := NewMemoryStore()
	mgr := NewManager(store)

	result, err := mgr.Evaluate(context.Background(), "user-1", DeviceInfo{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.IsNewDevice {
		t.Error("empty fingerprint should evaluate as new device")
	}
	if !result.RequiresMFA {
		t.Error("empty fingerprint should require MFA")
	}
}

func TestManager_Block(t *testing.T) {
	store := NewMemoryStore()
	mgr := NewManager(store)
	ctx := context.Background()

	dev, _ := mgr.Register(ctx, "user-1", DeviceInfo{Fingerprint: "fp-block"})
	mgr.Verify(ctx, dev.ID)

	err := mgr.Block(ctx, dev.ID)
	if err != nil {
		t.Fatalf("block failed: %v", err)
	}

	// Verify blocked device cannot be verified
	err = mgr.Verify(ctx, dev.ID)
	if err == nil {
		t.Fatal("expected error verifying blocked device")
	}

	// Evaluate blocked device
	result, _ := mgr.Evaluate(ctx, "user-1", DeviceInfo{Fingerprint: "fp-block"})
	if result.TrustLevel != TrustBlocked {
		t.Errorf("expected TrustBlocked, got %q", result.TrustLevel)
	}
	if !result.RequiresMFA {
		t.Error("blocked device should require MFA")
	}
}

func TestManager_RevokeAll(t *testing.T) {
	store := NewMemoryStore()
	mgr := NewManager(store)
	ctx := context.Background()

	mgr.Register(ctx, "user-1", DeviceInfo{Fingerprint: "fp-1"})
	mgr.Register(ctx, "user-1", DeviceInfo{Fingerprint: "fp-2"})
	mgr.Register(ctx, "user-1", DeviceInfo{Fingerprint: "fp-3"})

	devices, _ := mgr.ListDevices(ctx, "user-1")
	if len(devices) != 3 {
		t.Fatalf("expected 3 devices, got %d", len(devices))
	}

	err := mgr.RevokeAll(ctx, "user-1")
	if err != nil {
		t.Fatalf("revoke all failed: %v", err)
	}

	devices, _ = mgr.ListDevices(ctx, "user-1")
	if len(devices) != 0 {
		t.Errorf("expected 0 devices after revoke, got %d", len(devices))
	}
}

func TestManager_AutoTrustUpgrade(t *testing.T) {
	store := NewMemoryStore()
	mgr := NewManager(store, WithAutoTrustAfter(1*time.Millisecond))
	ctx := context.Background()

	dev, _ := mgr.Register(ctx, "user-1", DeviceInfo{Fingerprint: "fp-auto"})
	mgr.Verify(ctx, dev.ID)

	// Wait for auto-trust threshold
	time.Sleep(5 * time.Millisecond)

	result, _ := mgr.Evaluate(ctx, "user-1", DeviceInfo{Fingerprint: "fp-auto"})
	if result.TrustLevel != TrustHigh {
		t.Errorf("expected TrustHigh after auto-trust, got %q", result.TrustLevel)
	}
}
