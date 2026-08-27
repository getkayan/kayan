package policy

import (
	"context"
	"errors"
	"testing"
)

var errEngineDown = errors.New("policy engine unavailable")

// stubEngine answers with a fixed result, or fails.
type stubEngine struct {
	allowed bool
	err     error
}

func (e stubEngine) Can(ctx context.Context, subject any, action string, resource any) (bool, error) {
	return e.allowed, e.err
}

// TestAllowOverridesReportsEngineFailure covers a silent wrong denial.
//
// AllowOverrides discarded every engine error. When the store behind an engine
// is unavailable, each Can returns (false, err), the loop drops the error, and
// the function returns (false, nil) -- an authoritative "denied" that is
// indistinguishable from a real decision.
//
// A caller cannot tell an outage from a policy result, so a database problem
// surfaces as users being denied access they have, with nothing in the error
// path to say otherwise. The repository's rule is that a wrong allow is worse
// than a crash; a wrong deny reported as a clean answer is the same failure in
// the other direction, and it is the one that pages nobody.
func TestAllowOverridesReportsEngineFailure(t *testing.T) {
	strategy := NewHybridStrategy(AllowOverrides,
		stubEngine{err: errEngineDown},
		stubEngine{err: errEngineDown},
	)

	allowed, err := strategy.Can(context.Background(), "alice", "read", "doc-1")
	if err == nil {
		t.Fatalf("every engine failed but Can returned (%v, nil)", allowed)
	}
	if !errors.Is(err, errEngineDown) {
		t.Errorf("error = %v, want it to wrap the engine failure", err)
	}
	if allowed {
		t.Error("Can allowed access while every engine was failing")
	}
}

// TestAllowOverridesStillAllowsOnSuccess keeps the override semantics: one
// engine allowing is enough, and an unrelated engine's failure must not veto
// a decision that was actually made.
func TestAllowOverridesStillAllowsOnSuccess(t *testing.T) {
	strategy := NewHybridStrategy(AllowOverrides,
		stubEngine{err: errEngineDown},
		stubEngine{allowed: true},
	)

	allowed, err := strategy.Can(context.Background(), "alice", "read", "doc-1")
	if err != nil {
		t.Fatalf("Can: %v", err)
	}
	if !allowed {
		t.Error("an engine allowed access but Can denied it")
	}
}

// TestAllowOverridesDeniesCleanly covers the ordinary negative answer: every
// engine responded and none allowed, so the denial is a real decision and must
// not be dressed up as an error.
func TestAllowOverridesDeniesCleanly(t *testing.T) {
	strategy := NewHybridStrategy(AllowOverrides,
		stubEngine{allowed: false},
		stubEngine{allowed: false},
	)

	allowed, err := strategy.Can(context.Background(), "alice", "read", "doc-1")
	if err != nil {
		t.Fatalf("a decided denial returned an error: %v", err)
	}
	if allowed {
		t.Error("no engine allowed access but Can allowed it")
	}
}
