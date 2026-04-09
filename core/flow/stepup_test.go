package flow

import (
	"context"
	"testing"
	"time"
)

// --- Mock Step-Up Policy ---

type mockStepUpPolicy struct {
	levels map[string]StepUpLevel
}

func (p *mockStepUpPolicy) RequiredLevel(ctx context.Context, action string, resource any) StepUpLevel {
	if level, ok := p.levels[action]; ok {
		return level
	}
	return StepUpNone
}

func TestStepUpManager_Evaluate(t *testing.T) {
	tests := []struct {
		name          string
		action        string
		existingLevel *StepUpLevel
		recency       time.Duration
		wantAllowed   bool
		wantRequired  StepUpLevel
	}{
		{
			name:         "no policy required - allowed",
			action:       "view_profile",
			wantAllowed:  true,
			wantRequired: StepUpNone,
		},
		{
			name:         "recent required - no record - denied",
			action:       "view_transactions",
			wantAllowed:  false,
			wantRequired: StepUpRecent,
		},
		{
			name:          "recent required - has recent password - allowed",
			action:        "view_transactions",
			existingLevel: stepUpLevelPtr(StepUpPassword),
			recency:       1 * time.Minute,
			wantAllowed:   true,
			wantRequired:  StepUpRecent,
		},
		{
			name:          "password required - has MFA only - denied",
			action:        "change_password",
			existingLevel: stepUpLevelPtr(StepUpMFA),
			recency:       1 * time.Minute,
			wantAllowed:   false,
			wantRequired:  StepUpPassword,
		},
		{
			name:          "password required - has password - allowed",
			action:        "change_password",
			existingLevel: stepUpLevelPtr(StepUpPassword),
			recency:       1 * time.Minute,
			wantAllowed:   true,
			wantRequired:  StepUpPassword,
		},
		{
			name:          "MFA required - expired recency - denied",
			action:        "transfer_funds",
			existingLevel: stepUpLevelPtr(StepUpMFA),
			recency:       30 * time.Minute, // Expired
			wantAllowed:   false,
			wantRequired:  StepUpMFA,
		},
	}

	policy := &mockStepUpPolicy{
		levels: map[string]StepUpLevel{
			"view_transactions": StepUpRecent,
			"transfer_funds":    StepUpMFA,
			"change_password":   StepUpPassword,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			store := NewMemoryStepUpStore()
			mgr := NewStepUpManager(store,
				WithStepUpPolicy(policy),
				WithRecencyWindow(15*time.Minute),
			)

			// Pre-record a step-up if specified
			if tt.existingLevel != nil {
				record := &StepUpRecord{
					SessionID:   "sess-1",
					Level:       *tt.existingLevel,
					CompletedAt: time.Now().Add(-tt.recency),
				}
				store.SaveStepUp(context.Background(), record)
			}

			result, err := mgr.Evaluate(context.Background(), "sess-1", tt.action, nil)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if result.Allowed != tt.wantAllowed {
				t.Errorf("allowed: got %v, want %v", result.Allowed, tt.wantAllowed)
			}
			if result.RequiredLevel != tt.wantRequired {
				t.Errorf("required level: got %q, want %q", result.RequiredLevel, tt.wantRequired)
			}
		})
	}
}

func TestStepUpManager_RecordAndEvaluate(t *testing.T) {
	store := NewMemoryStepUpStore()
	policy := &mockStepUpPolicy{
		levels: map[string]StepUpLevel{
			"sensitive_action": StepUpMFA,
		},
	}
	mgr := NewStepUpManager(store, WithStepUpPolicy(policy))
	ctx := context.Background()

	// Initially denied
	result, _ := mgr.Evaluate(ctx, "sess-1", "sensitive_action", nil)
	if result.Allowed {
		t.Fatal("should be denied before step-up")
	}

	// Record step-up
	err := mgr.RecordStepUp(ctx, "sess-1", StepUpMFA)
	if err != nil {
		t.Fatalf("record step-up failed: %v", err)
	}

	// Now allowed
	result, _ = mgr.Evaluate(ctx, "sess-1", "sensitive_action", nil)
	if !result.Allowed {
		t.Fatal("should be allowed after step-up")
	}
}

func TestStepUpManager_NoPolicy(t *testing.T) {
	store := NewMemoryStepUpStore()
	mgr := NewStepUpManager(store) // No policy

	result, err := mgr.Evaluate(context.Background(), "sess-1", "any_action", nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Allowed {
		t.Error("no policy should allow everything")
	}
}

func stepUpLevelPtr(l StepUpLevel) *StepUpLevel {
	return &l
}
