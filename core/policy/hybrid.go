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
		// OR logic: Return true if ANY engine returns true.
		// Errors are ignored unless ALL fail? Or log?
		// Common pattern: If one allows, allow.
		for _, e := range s.engines {
			allowed, err := e.Can(ctx, subject, action, resource)
			if err == nil && allowed {
				return true, nil
			}
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
