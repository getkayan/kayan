package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"

	"github.com/getkayan/kayan/flow"
	"github.com/getkayan/kayan/identity"
	"github.com/getkayan/kayan/persistence"
	"github.com/google/uuid"
)

// =============================================================================
// TYPED WRAPPER PATTERN
// Decorate Kayan's Identity with type-safe accessors for 'Traits'.
// =============================================================================

type User struct {
	*identity.Identity
}

func WrapUser(i any) *User {
	return &User{Identity: i.(*identity.Identity)}
}

// GetEmail handles extraction from the dynamic JSON Traits field
func (u *User) GetEmail() string {
	return u.getTraitString("email")
}

// GetFullName handles extraction from the dynamic JSON Traits field
func (u *User) GetFullName() string {
	return u.getTraitString("full_name")
}

func (u *User) getTraitString(key string) string {
	var traits map[string]any
	if err := json.Unmarshal(u.Traits, &traits); err != nil {
		return ""
	}
	if val, ok := traits[key].(string); ok {
		return val
	}
	return ""
}

func main() {
	// 1. Setup Kayan
	storage, err := persistence.NewStorage("sqlite", "kayan_auth_wrapper.db", nil)
	if err != nil {
		log.Fatalf("failed to initialize storage: %v", err)
	}
	factory := func() any { return &identity.Identity{} }
	regManager := flow.NewRegistrationManager(storage, factory)
	loginManager := flow.NewLoginManager(storage)

	hasher := flow.NewBcryptHasher(14)
	pwStrategy := flow.NewPasswordStrategy(storage, hasher, "email", factory)

	// Configure ID generation for UUIDs
	pwStrategy.SetIDGenerator(func() any { return uuid.New() })

	regManager.RegisterStrategy(pwStrategy)
	loginManager.RegisterStrategy(pwStrategy)

	// 2. Register a User
	fmt.Println("--- REGISTRATION PHASE ---")
	fmt.Println("Registering user...")
	traits := identity.JSON(`{"email": "typed@example.com", "full_name": "Typed User"}`)
	ident, _ := regManager.Submit(context.Background(), "password", traits, "password123")
	fmt.Printf("✓ Registered Identity: %s\n", ident.(*identity.Identity).ID)

	// 3. THE CORE PATTERN: Wrap the result for type safety
	user := WrapUser(ident)
	fmt.Printf("Type-Safe Access (via Wrapper): Email=%s, Name=%s\n", user.GetEmail(), user.GetFullName())

	// 4. Login
	fmt.Println("\n--- LOGIN PHASE ---")
	fmt.Println("Attempting login...")
	loggedInIdent, err := loginManager.Authenticate(context.Background(), "password", "typed@example.com", "password123")
	if err != nil {
		log.Fatalf("Login failed: %v", err)
	}
	fmt.Printf("✓ Login Success for: %s\n", loggedInIdent.(*identity.Identity).ID)

	// Wrap the logged in user as well
	loggedInUser := WrapUser(loggedInIdent)
	fmt.Printf("Parsed user email via wrapper: %s\n", loggedInUser.GetEmail())
}
