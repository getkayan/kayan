package mfa

import (
	"context"
	"fmt"
	"sync"
)

// MemoryStore is an in-memory implementation of MFAStore for development and testing.
type MemoryStore struct {
	mu            sync.RWMutex
	enrollments   map[string]*Enrollment
	challenges    map[string]*Challenge
	recoveryCodes map[string][]string // identityID -> codes
}

// NewMemoryStore creates a new in-memory MFA store.
func NewMemoryStore() *MemoryStore {
	return &MemoryStore{
		enrollments:   make(map[string]*Enrollment),
		challenges:    make(map[string]*Challenge),
		recoveryCodes: make(map[string][]string),
	}
}

func (s *MemoryStore) SaveEnrollment(ctx context.Context, enrollment *Enrollment) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.enrollments[enrollment.ID] = enrollment
	return nil
}

func (s *MemoryStore) GetEnrollment(ctx context.Context, id string) (*Enrollment, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	e, ok := s.enrollments[id]
	if !ok {
		return nil, fmt.Errorf("mfa: enrollment not found: %s", id)
	}
	return e, nil
}

func (s *MemoryStore) GetEnrollmentsByIdentity(ctx context.Context, identityID string) ([]*Enrollment, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var result []*Enrollment
	for _, e := range s.enrollments {
		if e.IdentityID == identityID {
			result = append(result, e)
		}
	}
	return result, nil
}

func (s *MemoryStore) UpdateEnrollment(ctx context.Context, enrollment *Enrollment) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.enrollments[enrollment.ID]; !ok {
		return fmt.Errorf("mfa: enrollment not found: %s", enrollment.ID)
	}
	s.enrollments[enrollment.ID] = enrollment
	return nil
}

func (s *MemoryStore) DeleteEnrollment(ctx context.Context, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.enrollments, id)
	return nil
}

func (s *MemoryStore) SaveChallenge(ctx context.Context, challenge *Challenge) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.challenges[challenge.ID] = challenge
	return nil
}

func (s *MemoryStore) GetChallenge(ctx context.Context, id string) (*Challenge, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	c, ok := s.challenges[id]
	if !ok {
		return nil, fmt.Errorf("mfa: challenge not found: %s", id)
	}
	return c, nil
}

func (s *MemoryStore) DeleteChallenge(ctx context.Context, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.challenges, id)
	return nil
}

func (s *MemoryStore) SaveRecoveryCodes(ctx context.Context, identityID string, codes []string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.recoveryCodes[identityID] = codes
	return nil
}

func (s *MemoryStore) GetRecoveryCodes(ctx context.Context, identityID string) ([]string, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	codes, ok := s.recoveryCodes[identityID]
	if !ok {
		return nil, fmt.Errorf("mfa: no recovery codes for identity: %s", identityID)
	}
	return codes, nil
}

func (s *MemoryStore) ConsumeRecoveryCode(ctx context.Context, identityID, code string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	codes, ok := s.recoveryCodes[identityID]
	if !ok {
		return fmt.Errorf("mfa: no recovery codes for identity: %s", identityID)
	}

	filtered := make([]string, 0, len(codes))
	found := false
	for _, c := range codes {
		if c == code {
			found = true
			continue
		}
		filtered = append(filtered, c)
	}

	if !found {
		return fmt.Errorf("mfa: recovery code not found")
	}

	s.recoveryCodes[identityID] = filtered
	return nil
}
