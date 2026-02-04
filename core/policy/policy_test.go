package policy

import (
	"context"
	"testing"

	"github.com/getkayan/kayan/core/identity"
	"github.com/getkayan/kayan/core/rbac"
)

// Mock RoleSource
type mockUser struct {
	Roles []string
}

func (m *mockUser) GetRoles() []string { return m.Roles }

// Test RBAC
func TestRBAC(t *testing.T) {
	// 1. Setup
	rbacStrategy := rbac.NewBasicStrategy(nil) // Storage nil as we rely on RoleSource interface optimization

	// 2. Test Allowed
	admin := &mockUser{Roles: []string{"admin", "editor"}}
	ok, _ := rbacStrategy.Can(context.Background(), admin, "admin", nil)
	if !ok {
		t.Error("RBAC should allow admin")
	}

	// 3. Test Denied
	guest := &mockUser{Roles: []string{"guest"}}
	ok, _ = rbacStrategy.Can(context.Background(), guest, "admin", nil)
	if ok {
		t.Error("RBAC should deny guest")
	}
}

// Test ABAC
type Post struct {
	OwnerID string
	Public  bool
}

func TestABAC(t *testing.T) {
	abac := NewABACStrategy()

	// Rule: Owner can edit
	abac.AddRule("edit_post", func(ctx context.Context, sub, res any, pCtx Context) (bool, error) {
		user, ok := sub.(*identity.Identity)
		if !ok {
			return false, nil
		}
		post, ok := res.(*Post)
		if !ok {
			return false, nil
		}
		return user.ID == post.OwnerID, nil
	})

	// Rule: Context check (IP)
	abac.AddRule("vpn_access", func(ctx context.Context, sub, res any, pCtx Context) (bool, error) {
		ip := pCtx["ip"]
		return ip == "10.0.0.1", nil
	})

	// Test Owner
	user := &identity.Identity{ID: "user1"}
	post := &Post{OwnerID: "user1"}
	ok, _ := abac.Can(context.Background(), user, "edit_post", post)
	if !ok {
		t.Error("ABAC should allow owner to edit")
	}

	// Test Non-Owner
	otherPost := &Post{OwnerID: "user2"}
	ok, _ = abac.Can(context.Background(), user, "edit_post", otherPost)
	if ok {
		t.Error("ABAC should deny non-owner")
	}

	// Test Context
	ctx := WithContext(context.Background(), Context{"ip": "10.0.0.1"})
	ok, _ = abac.Can(ctx, user, "vpn_access", nil)
	if !ok {
		t.Error("ABAC should allow valid IP")
	}

	ctxBad := WithContext(context.Background(), Context{"ip": "192.168.1.1"})
	ok, _ = abac.Can(ctxBad, user, "vpn_access", nil)
	if ok {
		t.Error("ABAC should deny invalid IP")
	}
}

// Test Hybrid
func TestHybrid(t *testing.T) {
	// Hybrid: Must be Admin (RBAC) AND Owner (ABAC) - strict!
	rbacStrategy := rbac.NewBasicStrategy(nil)
	abac := NewABACStrategy()
	abac.AddRule("delete", func(ctx context.Context, sub, res any, pCtx Context) (bool, error) {
		// Mock owner check
		return true, nil
	})

	hybrid := NewHybridStrategy(DenyOverrides, rbacStrategy, abac)

	// User is Admin (Passes RBAC) BUT ABAC check is mocked true.
	// Actually let's make ABAC conditional so we verify AND logic.

	// Complex Scenario:
	// Action: "delete"
	// RBAC requires role "delete" (simplistic)
	// ABAC requires mock true.

	// 1. User has role, ABAC true -> Allow
	user := &mockUser{Roles: []string{"delete"}}
	ok, _ := hybrid.Can(context.Background(), user, "delete", nil)
	if !ok {
		t.Error("Hybrid(AND) should allow if both pass")
	}

	// 2. User no role, ABAC true -> Deny (because RBAC fails)
	userNoRole := &mockUser{Roles: []string{"guest"}}
	ok, _ = hybrid.Can(context.Background(), userNoRole, "delete", nil)
	if ok {
		t.Error("Hybrid(AND) should deny if one fails")
	}
}
