package main

import (
	"context"
	"fmt"
	"log"
	"os"

	"github.com/getkayan/kayan/flow"
	"github.com/getkayan/kayan/identity"
	"github.com/getkayan/kayan/persistence"
)

func main() {
	// 1. Setup Kayan Storage with uint (Auto-Increment)
	dbPath := "autoincrement_ids.db"
	defer os.Remove(dbPath)

	// We use uint here. SQLite/GORM will handle auto-increment by default.
	storage, err := persistence.NewStorage[uint]("sqlite", dbPath, nil)
	if err != nil {
		log.Fatalf("failed to initialize storage: %v", err)
	}

	// 2. Setup Kayan Managers
	regManager := flow.NewRegistrationManager(storage)
	loginManager := flow.NewLoginManager(storage)

	// Setup Password Strategy (NO IDGenerator provided)
	// When generator is nil, the ID is submitted as 0,
	// which GORM interprets as a request for auto-increment.
	hasher := flow.NewBcryptHasher(14)
	pwStrategy := flow.NewPasswordStrategy(storage, hasher, "email")

	regManager.RegisterStrategy(pwStrategy)
	loginManager.RegisterStrategy(pwStrategy)

	// 3. DEMONSTRATION: Registration
	fmt.Println("--- REGISTRATION PHASE ---")
	traits := identity.JSON(`{"email": "increment@example.com"}`)
	ident, err := regManager.Submit(context.Background(), "password", traits, "secure-pass")
	if err != nil {
		log.Fatalf("registration failed: %v", err)
	}

	fmt.Printf("✓ Registered Identity with Auto-Increment ID: %d\n", ident.ID)

	// Register another one
	traits2 := identity.JSON(`{"email": "second@example.com"}`)
	ident2, err := regManager.Submit(context.Background(), "password", traits2, "secure-pass")
	if err != nil {
		log.Fatalf("registration failed: %v", err)
	}
	fmt.Printf("✓ Registered Second Identity with Auto-Increment ID: %d\n", ident2.ID)

	// 4. DEMONSTRATION: Login
	fmt.Println("\n--- LOGIN PHASE ---")
	loggedIn, err := loginManager.Authenticate(context.Background(), "password", "increment@example.com", "secure-pass")
	if err != nil {
		log.Fatalf("login failed: %v", err)
	}

	fmt.Printf("✓ Success! Logged in with ID: %d\n", loggedIn.ID)

	fmt.Printf("\nVerification complete: IDs are auto-incremented by the database.\n")
}
