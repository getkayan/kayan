package policy

import (
	"context"
)

// Engine defines the core interface for making authorization decisions.
// It is generic to support various paradigms (RBAC, ABAC, ReBAC).
type Engine interface {
	// Can checks if the subject can perform the action on the resource within the given context.
	Can(ctx context.Context, subject any, action string, resource any) (bool, error)
}

// Context is a flexible map for passing environmental or additional data to the policy engine.
// Examples: IP address, time of day, request headers.
type Context map[string]any

// Factory defines a function that creates a new policy engine instance.
// This is useful for dependency injection or dynamic configuration.
type Factory func(config map[string]any) (Engine, error)
