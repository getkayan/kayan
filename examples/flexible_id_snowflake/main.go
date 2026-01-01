package main

import (
	"context"
	"fmt"
	"log"
	"os"

	"github.com/bwmarrin/snowflake"
	"github.com/getkayan/kayan/flow"
	"github.com/getkayan/kayan/identity"
	"github.com/getkayan/kayan/persistence"
)

func main() {
	// 1. Setup Snowflake Node (Distributed ID Generator)
	node, err := snowflake.NewNode(1)
	if err != nil {
		log.Fatalf("failed to create snowflake node: %v", err)
	}

	// 2. Setup Kayan Storage with int64 IDs
	dbPath := "snowflake_ids.db"
	defer os.Remove(dbPath)

	type Ident struct {
		identity.Identity
		ID int64 `gorm:"primaryKey"` // Override to int64
	}

	storage, err := persistence.NewStorage("sqlite", dbPath, nil, &Ident{})
	if err != nil {
		log.Fatalf("failed to initialize storage: %v", err)
	}

	// 3. Setup Kayan Managers
	factory := func() any { return &Ident{} }
	regManager := flow.NewRegistrationManager(storage, factory)
	loginManager := flow.NewLoginManager(storage)

	// Setup Password Strategy with Snowflake ID Generator
	hasher := flow.NewBcryptHasher(14)
	pwStrategy := flow.NewPasswordStrategy(storage, hasher, "email", factory)

	// CONFIGURE THE SNOWFLAKE GENERATOR
	pwStrategy.SetIDGenerator(func() any {
		return int64(node.Generate())
	})

	regManager.RegisterStrategy(pwStrategy)
	loginManager.RegisterStrategy(pwStrategy)

	// 4. DEMONSTRATION: Registration
	fmt.Println("--- REGISTRATION PHASE ---")
	traits := identity.JSON(`{"email": "snowflake@example.com"}`)
	ident, err := regManager.Submit(context.Background(), "password", traits, "secure-pass")
	if err != nil {
		log.Fatalf("registration failed: %v", err)
	}

	fmt.Printf("✓ Registered Identity with Snowflake ID: %d\n", ident.(*Ident).ID)

	// 5. DEMONSTRATION: Login
	fmt.Println("\n--- LOGIN PHASE ---")
	loggedIn, err := loginManager.Authenticate(context.Background(), "password", "snowflake@example.com", "secure-pass")
	if err != nil {
		log.Fatalf("login failed: %v", err)
	}

	fmt.Printf("✓ Success! Logged in with Snowflake ID: %d\n", loggedIn.(*Ident).ID)

	// Verify ID consistency
	if ident.(*Ident).ID != loggedIn.(*Ident).ID {
		log.Fatal("Assertion failed: identities do not match")
	}

	fmt.Printf("\nVerification complete: IDs are stored as int64 (Snowflake).\n")
}
