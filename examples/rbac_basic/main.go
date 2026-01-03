package main

import (
	"encoding/json"
	"fmt"
	"log"

	"github.com/getkayan/kayan/identity"
	"github.com/getkayan/kayan/rbac"
)

// MockIdentityStorage implements domain.IdentityStorage for testing RBAC
type MockIdentityStorage struct {
	identities map[string]*identity.Identity
}

func (m *MockIdentityStorage) CreateIdentity(ident any) error {
	i := ident.(*identity.Identity)
	m.identities[i.ID] = i
	return nil
}

func (m *MockIdentityStorage) GetIdentity(factory func() any, id any) (any, error) {
	ident, ok := m.identities[fmt.Sprintf("%v", id)]
	if !ok {
		return nil, fmt.Errorf("identity not found")
	}
	return ident, nil
}

func (m *MockIdentityStorage) FindIdentity(factory func() any, query map[string]any) (any, error) {
	return nil, nil // Not needed for this example
}

func (m *MockIdentityStorage) GetCredentialByIdentifier(identifier string, method string) (*identity.Credential, error) {
	return nil, nil // Not needed for this example
}

func main() {
	storage := &MockIdentityStorage{identities: make(map[string]*identity.Identity)}

	// 1. Setup Identity with Roles
	roles, _ := json.Marshal([]string{"admin", "editor"})
	user := &identity.Identity{
		ID:    "user_1",
		Roles: roles,
	}
	storage.CreateIdentity(user)

	// 2. Setup RBAC
	// BasicStrategy reads roles directly from the identity model in storage
	strategy := rbac.NewBasicStrategy(storage)
	manager := rbac.NewManager(strategy)

	// 3. Test Authorization
	fmt.Println("Checking roles for user_1...")

	isAdmin, _ := manager.Authorize("user_1", "admin")
	fmt.Printf("Is Admin: %v\n", isAdmin)

	isEditor, _ := manager.Authorize("user_1", "editor")
	fmt.Printf("Is Editor: %v\n", isEditor)

	isViewer, _ := manager.Authorize("user_1", "viewer")
	fmt.Printf("Is Viewer: %v\n", isViewer)

	// 4. Test RequireRole (Helper)
	err := manager.RequireRole("user_1", "admin")
	if err != nil {
		log.Fatalf("expected admin access: %v", err)
	}
	fmt.Println("Access granted for role: admin")

	err = manager.RequireRole("user_1", "viewer")
	if err != nil {
		fmt.Printf("Access denied for role viewer: %v\n", err)
	}
}
