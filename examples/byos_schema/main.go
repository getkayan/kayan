package main

import (
	"context"
	"fmt"
	"log"
	"os"

	"github.com/getkayan/kayan/flow"
	"github.com/getkayan/kayan/identity"
	"github.com/getkayan/kayan/persistence"
	"github.com/google/uuid"
)

// =============================================================================
// BRING YOUR OWN SCHEMA (BYOS)
// This model does NOT embed identity.Identity.
// It is a completely custom schema with direct fields for identifiers and secrets.
// =============================================================================

type MyUser struct {
	ID           uuid.UUID `gorm:"type:uuid;primaryKey"`
	Email        string    `gorm:"uniqueIndex"`
	Username     string    `gorm:"uniqueIndex"`
	PasswordHash string
	DisplayName  string
}

// FlowIdentity implementation is required for ID management
func (u *MyUser) GetID() any   { return u.ID }
func (u *MyUser) SetID(id any) { u.ID = id.(uuid.UUID) }

func main() {
	dbPath := "byos.db"
	os.Remove(dbPath)
	defer os.Remove(dbPath)

	// 1. Initialize Storage with the custom model
	storage, err := persistence.NewStorage("sqlite", dbPath, nil, &MyUser{})
	if err != nil {
		log.Fatalf("failed to initialize storage: %v", err)
	}

	// 2. Setup Managers
	factory := func() any { return &MyUser{} }
	regManager := flow.NewRegistrationManager(storage, factory)
	loginManager := flow.NewLoginManager(storage)

	// 3. Setup Password Strategy with FIELD MAPPING
	hasher := flow.NewBcryptHasher(14)
	pwStrategy := flow.NewPasswordStrategy(storage, hasher, "", factory)

	// THE BYOS MAGIC:
	// Maps 'Email' and 'Username' traits to the struct fields.
	// Maps the password secret to 'PasswordHash'.
	pwStrategy.MapFields([]string{"Email", "Username"}, "PasswordHash")
	pwStrategy.SetIDGenerator(func() any { return uuid.New() })

	regManager.RegisterStrategy(pwStrategy)
	loginManager.RegisterStrategy(pwStrategy)

	// 4. DEMONSTRATION: Registration
	fmt.Println("--- REGISTRATION (BYOS) ---")
	// Traits are provided as JSON, and the strategy will extract the mapped fields
	traits := identity.JSON(`{"Email": "boss@example.com", "Username": "the_boss", "DisplayName": "Big Boss"}`)
	ident, err := regManager.Submit(context.Background(), "password", traits, "password123")
	if err != nil {
		log.Fatalf("registration failed: %v", err)
	}

	user := ident.(*MyUser)
	fmt.Printf("✓ Success! Created custom MyUser model directly:\n")
	fmt.Printf("  ID:    %s\n", user.ID)
	fmt.Printf("  Email: %s\n", user.Email)
	fmt.Printf("  Hash:  %s...\n", user.PasswordHash[:20])

	// 5. DEMONSTRATION: Authentication via Email
	fmt.Println("\n--- LOGIN (via Email) ---")
	loggedIn, err := loginManager.Authenticate(context.Background(), "password", "boss@example.com", "password123")
	if err != nil {
		log.Fatalf("login failed: %v", err)
	}
	fmt.Printf("✓ Authenticated: %s (ID: %s)\n", loggedIn.(*MyUser).Username, loggedIn.(*MyUser).ID)

	// 6. DEMONSTRATION: Authentication via Username
	fmt.Println("\n--- LOGIN (via Username) ---")
	loggedIn, err = loginManager.Authenticate(context.Background(), "password", "the_boss", "password123")
	if err != nil {
		log.Fatalf("login failed: %v", err)
	}
	fmt.Printf("✓ Authenticated: %s (Email: %s)\n", loggedIn.(*MyUser).Username, loggedIn.(*MyUser).Email)

	fmt.Println("\nSUCCESS: Kayan worked directly with your custom schema using field mapping!")
}
