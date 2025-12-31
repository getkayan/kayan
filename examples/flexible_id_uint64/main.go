package main

import (
	"context"
	"fmt"
	"log"

	"github.com/getkayan/kayan/flow"
	"github.com/getkayan/kayan/identity"
	"github.com/getkayan/kayan/persistence"
)

func main() {
	// 1. Setup Kayan storage for uint64 IDs
	// We use the same 'sqlite' provider but specify uint64 as the generic parameter
	storage, err := persistence.NewStorage[uint64]("sqlite", "flexible_uint64.db", nil)
	if err != nil {
		log.Fatalf("Failed to setup storage: %v", err)
	}

	// 2. Setup Managers for uint64 IDs
	regManager := flow.NewRegistrationManager[uint64](storage)
	loginManager := flow.NewLoginManager[uint64](storage)

	// 3. Register Strategy (Password)
	hasher := flow.NewBcryptHasher(14)
	pwStrategy := flow.NewPasswordStrategy[uint64](storage, hasher, "email")
	regManager.RegisterStrategy(pwStrategy)
	loginManager.RegisterStrategy(pwStrategy)

	// --- REGISTRATION ---
	fmt.Println("--- REGISTRATION PHASE ---")
	traits := identity.JSON(`{"email": "uint64@example.com", "name": "Generic User"}`)

	// In this example, we let the database handle ID generation (Auto-Increment)
	// So we pass an Identity with a zero ID.
	ident, err := regManager.Submit(context.Background(), "password", traits, "password123")
	if err != nil {
		log.Fatalf("Registration failed: %v", err)
	}
	fmt.Printf("✓ Registered Identity with uint64 ID: %d\n", ident.ID)

	// --- LOGIN ---
	fmt.Println("\n--- LOGIN PHASE ---")
	loggedIn, err := loginManager.Authenticate(context.Background(), "password", "uint64@example.com", "password123")
	if err != nil {
		log.Fatalf("Login failed: %v", err)
	}
	fmt.Printf("✓ Success! Logged in with ID: %d\n", loggedIn.ID)

	// --- VERIFICATION ---
	fmt.Println("\nVerification complete: IDs are stored as uint64.")
}
