package policy

import (
	"context"
	"sync"
)

// Rule defines a function that evaluates a policy decision.
type Rule func(ctx context.Context, subject any, resource any, context Context) (bool, error)

// ABACStrategy implements Attribute-Based Access Control.
// It uses registered functional rules to determine access.
type ABACStrategy struct {
	mu    sync.RWMutex
	rules map[string]Rule
}

func NewABACStrategy() *ABACStrategy {
	return &ABACStrategy{
		rules: make(map[string]Rule),
	}
}

// AddRule registers a new policy rule for a specific action.
func (s *ABACStrategy) AddRule(action string, rule Rule) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.rules[action] = rule
}

// Can checks if there is a rule for the action and if it evaluates to true.
// The 'context' map can be passed in the generic Context or via the Go context.
// Kayan's policy interface doesn't explicitly pass the map `Context` in `Can` signature for simplicity,
// but we can extract it if needed or assume `resource` contains context.
// Wait, the generic engine signature is: Can(ctx, sub, act, res)
// We need to support passing extra context.
// Options:
// 1. Context keys.
// 2. Resource wrapper.
// Let's assume for ABAC, the caller passes a `policy.Context` map as part of the resource or separately?
// To keep interface generic `Can(sub, act, res)`, we should extract Context from `ctx` or `resource`.
// Let's modify the Engine interface? No, let's keep it standard.
// We'll extract `Context` from the `ctx context.Context` if available.
type contextKey struct{}

var PolicyContextKey = contextKey{}

func WithContext(ctx context.Context, pCtx Context) context.Context {
	return context.WithValue(ctx, PolicyContextKey, pCtx)
}

func (s *ABACStrategy) Can(ctx context.Context, subject any, action string, resource any) (bool, error) {
	s.mu.RLock()
	rule, ok := s.rules[action]
	s.mu.RUnlock()

	if !ok {
		// Default deny if no rule exists for this action?
		// Or should we support wildcard rules?
		return false, nil
	}

	// Extract extra context map
	var pCtx Context
	if val := ctx.Value(PolicyContextKey); val != nil {
		if c, ok := val.(Context); ok {
			pCtx = c
		}
	}
	if pCtx == nil {
		pCtx = make(Context)
	}

	return rule(ctx, subject, resource, pCtx)
}
