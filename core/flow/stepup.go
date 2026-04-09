package flow

import (
	"context"
	"fmt"
	"sync"
	"time"
)

// StepUpLevel represents the authentication assurance level required for an action.
type StepUpLevel string

const (
	// StepUpNone requires only a basic session — no additional authentication.
	StepUpNone StepUpLevel = "none"
	// StepUpRecent requires the user to have authenticated within a recency window.
	StepUpRecent StepUpLevel = "recent"
	// StepUpMFA requires the user to have completed MFA verification.
	StepUpMFA StepUpLevel = "mfa"
	// StepUpPassword requires the user to re-enter their password.
	StepUpPassword StepUpLevel = "password"
)

// StepUpPolicy defines when step-up authentication is required.
// Implementations map actions and resources to required assurance levels.
//
// Example:
//
//	type BankingPolicy struct{}
//	func (p *BankingPolicy) RequiredLevel(ctx context.Context, action string, resource any) StepUpLevel {
//	    switch action {
//	    case "transfer_funds", "change_password":
//	        return flow.StepUpPassword
//	    case "view_transactions":
//	        return flow.StepUpRecent
//	    default:
//	        return flow.StepUpNone
//	    }
//	}
type StepUpPolicy interface {
	RequiredLevel(ctx context.Context, action string, resource any) StepUpLevel
}

// StepUpResult contains the outcome of evaluating a step-up requirement.
type StepUpResult struct {
	// Allowed is true if the current session meets the required level.
	Allowed bool `json:"allowed"`
	// RequiredLevel is the level required for the action.
	RequiredLevel StepUpLevel `json:"required_level"`
	// CurrentLevel is the highest level the session currently has.
	CurrentLevel StepUpLevel `json:"current_level"`
	// ChallengeType suggests which authentication method to use if not allowed.
	ChallengeType string `json:"challenge_type,omitempty"`
}

// StepUpRecord tracks when a step-up authentication was completed for a session.
type StepUpRecord struct {
	SessionID   string      `json:"session_id"`
	Level       StepUpLevel `json:"level"`
	CompletedAt time.Time   `json:"completed_at"`
}

// StepUpStore persists step-up authentication records.
type StepUpStore interface {
	SaveStepUp(ctx context.Context, record *StepUpRecord) error
	GetStepUp(ctx context.Context, sessionID string) (*StepUpRecord, error)
	DeleteStepUp(ctx context.Context, sessionID string) error
}

// StepUpManager orchestrates step-up authentication checks.
//
// Usage:
//
//	store := flow.NewMemoryStepUpStore()
//	policy := &BankingPolicy{}
//	mgr := flow.NewStepUpManager(store, flow.WithStepUpPolicy(policy))
//
//	// Check before a sensitive action
//	result, _ := mgr.Evaluate(ctx, "session-123", "transfer_funds", nil)
//	if !result.Allowed {
//	    // Prompt user for re-authentication
//	}
//
//	// After re-authentication succeeds
//	mgr.RecordStepUp(ctx, "session-123", flow.StepUpPassword)
type StepUpManager struct {
	store          StepUpStore
	policy         StepUpPolicy
	recencyWindow  time.Duration
}

// StepUpManagerOption configures a StepUpManager.
type StepUpManagerOption func(*StepUpManager)

// WithStepUpPolicy sets the policy for determining required levels.
func WithStepUpPolicy(policy StepUpPolicy) StepUpManagerOption {
	return func(m *StepUpManager) { m.policy = policy }
}

// WithRecencyWindow sets how long a step-up authentication remains valid.
// Default is 15 minutes.
func WithRecencyWindow(d time.Duration) StepUpManagerOption {
	return func(m *StepUpManager) { m.recencyWindow = d }
}

// NewStepUpManager creates a new step-up authentication manager.
func NewStepUpManager(store StepUpStore, opts ...StepUpManagerOption) *StepUpManager {
	m := &StepUpManager{
		store:         store,
		recencyWindow: 15 * time.Minute,
	}
	for _, opt := range opts {
		opt(m)
	}
	return m
}

// Evaluate checks whether the current session meets the required assurance level
// for a given action.
func (m *StepUpManager) Evaluate(ctx context.Context, sessionID, action string, resource any) (*StepUpResult, error) {
	if m.policy == nil {
		return &StepUpResult{
			Allowed:       true,
			RequiredLevel: StepUpNone,
			CurrentLevel:  StepUpNone,
		}, nil
	}

	required := m.policy.RequiredLevel(ctx, action, resource)

	// No step-up needed
	if required == StepUpNone {
		return &StepUpResult{
			Allowed:       true,
			RequiredLevel: StepUpNone,
			CurrentLevel:  StepUpNone,
		}, nil
	}

	// Check existing step-up record
	record, err := m.store.GetStepUp(ctx, sessionID)
	if err != nil || record == nil {
		return &StepUpResult{
			Allowed:       false,
			RequiredLevel: required,
			CurrentLevel:  StepUpNone,
			ChallengeType: m.challengeTypeFor(required),
		}, nil
	}

	// Check recency
	if time.Since(record.CompletedAt) > m.recencyWindow {
		return &StepUpResult{
			Allowed:       false,
			RequiredLevel: required,
			CurrentLevel:  StepUpNone,
			ChallengeType: m.challengeTypeFor(required),
		}, nil
	}

	// Check if the recorded level meets the requirement
	if m.levelSatisfies(record.Level, required) {
		return &StepUpResult{
			Allowed:       true,
			RequiredLevel: required,
			CurrentLevel:  record.Level,
		}, nil
	}

	return &StepUpResult{
		Allowed:       false,
		RequiredLevel: required,
		CurrentLevel:  record.Level,
		ChallengeType: m.challengeTypeFor(required),
	}, nil
}

// RecordStepUp records that a step-up authentication was completed.
func (m *StepUpManager) RecordStepUp(ctx context.Context, sessionID string, level StepUpLevel) error {
	record := &StepUpRecord{
		SessionID:   sessionID,
		Level:       level,
		CompletedAt: time.Now(),
	}
	return m.store.SaveStepUp(ctx, record)
}

// levelSatisfies checks if the current level meets or exceeds the required level.
// Hierarchy: password > mfa > recent > none.
func (m *StepUpManager) levelSatisfies(current, required StepUpLevel) bool {
	order := map[StepUpLevel]int{
		StepUpNone:     0,
		StepUpRecent:   1,
		StepUpMFA:      2,
		StepUpPassword: 3,
	}
	return order[current] >= order[required]
}

func (m *StepUpManager) challengeTypeFor(level StepUpLevel) string {
	switch level {
	case StepUpPassword:
		return "password"
	case StepUpMFA:
		return "mfa"
	case StepUpRecent:
		return "reauthenticate"
	default:
		return ""
	}
}

// --- In-Memory StepUpStore ---

// MemoryStepUpStore is an in-memory implementation of StepUpStore for testing.
type MemoryStepUpStore struct {
	mu      sync.RWMutex
	records map[string]*StepUpRecord
}

// NewMemoryStepUpStore creates a new in-memory step-up store.
func NewMemoryStepUpStore() *MemoryStepUpStore {
	return &MemoryStepUpStore{
		records: make(map[string]*StepUpRecord),
	}
}

func (s *MemoryStepUpStore) SaveStepUp(ctx context.Context, record *StepUpRecord) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.records[record.SessionID] = record
	return nil
}

func (s *MemoryStepUpStore) GetStepUp(ctx context.Context, sessionID string) (*StepUpRecord, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	r, ok := s.records[sessionID]
	if !ok {
		return nil, fmt.Errorf("stepup: no record for session %s", sessionID)
	}
	return r, nil
}

func (s *MemoryStepUpStore) DeleteStepUp(ctx context.Context, sessionID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.records, sessionID)
	return nil
}
