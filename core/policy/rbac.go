package policy

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/getkayan/kayan/core/domain"
	"github.com/getkayan/kayan/core/identity"
	"github.com/google/uuid"
)

// RoleSource is an interface for identities that have roles.
// Models can implement this to speed up role retrieval.
type RoleSource interface {
	GetRoles() []string
}

// RBACStrategy implements Role-Based Access Control.
// It checks if the subject (identity) has the required role to perform the action.
// In this simple implementation, the 'action' is interpreted as the required 'role'.
// e.g. Can(ctx, user, "admin", nil) checks if user has role "admin".
//
// Deprecated: Consider using rbac.NewBasicStrategy instead, which also implements
// policy.Engine via its Can() method while providing additional role/permission helpers.
type RBACStrategy struct {
	storage domain.IdentityStorage
}

func NewRBACStrategy(storage domain.IdentityStorage) *RBACStrategy {
	return &RBACStrategy{storage: storage}
}

func (s *RBACStrategy) Can(ctx context.Context, subject any, action string, resource any) (bool, error) {
	// The 'action' here is treated as the underlying Role verification.
	// For example, if policy says "Can 'admin' resource", we check if user has 'admin' role.
	// This maps Can(ctx, user, "admin_dashboard", nil) -> requires "admin" role?
	// Or simplistic mapping: Action IS the Role.
	// Let's assume simplistic for now: Action == Role required.

	role := action

	// 1. Check if subject implements RoleSource (Optimization)
	if rs, ok := subject.(RoleSource); ok {
		for _, r := range rs.GetRoles() {
			if r == role {
				return true, nil
			}
		}
		return false, nil
	}

	// 2. Fallback to Storage Lookup (if subject is just an ID or generic)
	// If subject is an ID, we fetch it.
	var ident *identity.Identity
	var err error

	switch v := subject.(type) {
	case *identity.Identity:
		ident = v
	case string, int, int64, uuid.UUID: // IDs
		// Fetch from stroage
		var res any
		res, err = s.storage.GetIdentity(func() any { return &identity.Identity{} }, v)
		if err != nil {
			return false, err
		}
		if i, ok := res.(*identity.Identity); ok {
			ident = i
		}
	}

	if ident == nil {
		return false, fmt.Errorf("rbac: unable to resolve identity from subject")
	}

	// 3. Parse Roles from Identity
	if len(ident.Roles) == 0 {
		return false, nil
	}

	var roles []string
	if err := json.Unmarshal(ident.Roles, &roles); err != nil {
		return false, fmt.Errorf("rbac: failed to parse roles: %v", err)
	}

	for _, r := range roles {
		if r == role {
			return true, nil
		}
	}

	return false, nil
}
