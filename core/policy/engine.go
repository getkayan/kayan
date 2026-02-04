// Package policy provides authorization engines for Kayan IAM.
//
// The policy package implements flexible authorization using Attribute-Based
// Access Control (ABAC) and Hybrid (RBAC+ABAC) approaches. All policy engines
// implement the generic Engine interface.
//
// # ABAC (Attribute-Based Access Control)
//
// ABAC evaluates access based on subject attributes, resource attributes,
// and environmental context:
//
//	engine := policy.NewABACStrategy()
//	engine.AddRule("documents:read", func(ctx context.Context, subject, resource any, pCtx policy.Context) (bool, error) {
//	    user := subject.(*User)
//	    doc := resource.(*Document)
//	    return doc.OwnerID == user.ID || user.Role == "admin", nil
//	})
//
//	allowed, _ := engine.Can(ctx, user, "documents:read", document)
//
// # Hybrid (RBAC + ABAC)
//
// Combine role-based and attribute-based checks for maximum flexibility:
//
//	hybrid := policy.NewHybridStrategy(rbacEngine, abacEngine)
//	allowed, _ := hybrid.Can(ctx, subject, action, resource)
//
// # Engine Interface
//
// All authorization strategies implement the Engine interface:
//
//	type Engine interface {
//	    Can(ctx context.Context, subject any, action string, resource any) (bool, error)
//	}
//
// See also: rbac package for pure role-based access, rebac package for
// relationship-based access control.
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
