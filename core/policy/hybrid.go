package policy

import (
	"context"
	"fmt"
)

// Combinator defines how multiple policies are combined.
type Combinator int

const (
	// DenyOverrides: If any engine denies (returns false), result is false. All must allow.
	DenyOverrides Combinator = iota
	// AllowOverrides: If any engine allows (returns true), result is true.
	AllowOverrides
)

// HybridStrategy allows combining multiple authorization strategies.
type HybridStrategy struct {
	engines    []Engine
	combinator Combinator
}

// NewHybridStrategy creates a composed strategy.
// default combinator is DenyOverrides (AND logic).
func NewHybridStrategy(c Combinator, engines ...Engine) *HybridStrategy {
	return &HybridStrategy{
		engines:    engines,
		combinator: c,
	}
}

func (s *HybridStrategy) Can(ctx context.Context, subject any, action string, resource any) (bool, error) {
	if len(s.engines) == 0 {
		return false, fmt.Errorf("hybrid: no engines configured")
	}

	switch s.combinator {
	case AllowOverrides:
		// OR logic: allow if any engine allows.
		//
		// An engine that allows is a decision and ends the evaluation. An
		// engine that fails is not a denial: it is an unanswered question, and
		// the answer it would have given might have been "allow". Discarding
		// those errors turned an outage into (false, nil) -- a clean,
		// authoritative denial the caller could not distinguish from a real
		// one, so a failing store surfaced as users losing access they have,
		// with nothing in the error path to say why.
		//
		// So: allow wins immediately, and a denial is only returned when every
		// engine actually answered. Otherwise the failure is reported.
		var firstErr error
		for _, e := range s.engines {
			allowed, err := e.Can(ctx, subject, action, resource)
			if err != nil {
				if firstErr == nil {
					firstErr = err
				}
				continue
			}
			if allowed {
				return true, nil
			}
		}
		if firstErr != nil {
			return false, fmt.Errorf("hybrid: no engine allowed and at least one failed: %w", firstErr)
		}
		return false, nil

	case DenyOverrides:
		// AND logic: Return false if ANY engine returns false.
		// All must return true.
		for _, e := range s.engines {
			allowed, err := e.Can(ctx, subject, action, resource)
			if err != nil {
				return false, err
			}
			if !allowed {
				return false, nil
			}
		}
		return true, nil

	default:
		return false, fmt.Errorf("hybrid: unknown combinator")
	}
}
