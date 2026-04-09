package device

import (
	"context"
	"fmt"
	"sync"
)

// MemoryStore is an in-memory implementation of Store for development and testing.
type MemoryStore struct {
	mu      sync.RWMutex
	devices map[string]*Device // keyed by ID
}

// NewMemoryStore creates a new in-memory device store.
func NewMemoryStore() *MemoryStore {
	return &MemoryStore{
		devices: make(map[string]*Device),
	}
}

func (s *MemoryStore) SaveDevice(ctx context.Context, device *Device) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.devices[device.ID] = device
	return nil
}

func (s *MemoryStore) GetDevice(ctx context.Context, id string) (*Device, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	d, ok := s.devices[id]
	if !ok {
		return nil, fmt.Errorf("device: not found: %s", id)
	}
	return d, nil
}

func (s *MemoryStore) GetDeviceByFingerprint(ctx context.Context, identityID, fingerprint string) (*Device, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, d := range s.devices {
		if d.IdentityID == identityID && d.Fingerprint == fingerprint {
			return d, nil
		}
	}
	return nil, fmt.Errorf("device: not found for identity %s with fingerprint", identityID)
}

func (s *MemoryStore) GetDevicesByIdentity(ctx context.Context, identityID string) ([]*Device, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var result []*Device
	for _, d := range s.devices {
		if d.IdentityID == identityID {
			result = append(result, d)
		}
	}
	return result, nil
}

func (s *MemoryStore) UpdateDevice(ctx context.Context, device *Device) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.devices[device.ID]; !ok {
		return fmt.Errorf("device: not found: %s", device.ID)
	}
	s.devices[device.ID] = device
	return nil
}

func (s *MemoryStore) DeleteDevice(ctx context.Context, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.devices, id)
	return nil
}

func (s *MemoryStore) DeleteDevicesByIdentity(ctx context.Context, identityID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for id, d := range s.devices {
		if d.IdentityID == identityID {
			delete(s.devices, id)
		}
	}
	return nil
}
