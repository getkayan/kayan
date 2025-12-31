package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"time"

	"github.com/getkayan/kayan/flow"
	"github.com/getkayan/kayan/identity"
	"github.com/getkayan/kayan/persistence"
	"github.com/glebarez/sqlite"
	"github.com/google/uuid"
	"gorm.io/gorm"
)

// UserProfile is the application-specific model.
// It is stored in a separate table/database from Kayan's Identity.
type UserProfile struct {
	ID        uuid.UUID `gorm:"type:uuid;primaryKey"` // Maps to Identity.ID
	Email     string    `gorm:"uniqueIndex"`
	FullName  string
	BirthDate time.Time
	Role      string
}

func main() {
	// 1. Setup Application Database
	appDB, err := gorm.Open(sqlite.Open("app_users.db"), &gorm.Config{})
	if err != nil {
		log.Fatal(err)
	}
	appDB.AutoMigrate(&UserProfile{})

	// 2. Setup Kayan Storage
	storage, err := persistence.NewStorage[uuid.UUID]("sqlite", "kayan_auth.db", nil)
	if err != nil {
		log.Fatalf("failed to initialize storage: %v", err)
	}

	// 3. Setup Kayan Managers
	regManager := flow.NewRegistrationManager[uuid.UUID](storage)
	loginManager := flow.NewLoginManager[uuid.UUID](storage)

	// Register Password Strategy
	hasher := flow.NewBcryptHasher(14)
	pwStrategy := flow.NewPasswordStrategy[uuid.UUID](storage, hasher, "email")

	// Configure ID generation for UUIDs
	pwStrategy.SetIDGenerator(uuid.New)

	regManager.RegisterStrategy(pwStrategy)
	loginManager.RegisterStrategy(pwStrategy)

	// 4. THE CORE PATTERN: Registration Hook for Synchronization
	// This hook runs after Kayan creates the identity, allowing you to create your typed profile.
	regManager.AddPostHook(func(ctx context.Context, ident *identity.Identity[uuid.UUID]) error {
		fmt.Printf("[Sync Hook] Creating UserProfile for identity: %s\n", ident.ID)

		var traits struct {
			Email    string `json:"email"`
			FullName string `json:"full_name"`
			Role     string `json:"role"`
		}

		if err := json.Unmarshal(ident.Traits, &traits); err != nil {
			return err
		}

		profile := &UserProfile{
			ID:       ident.ID,
			Email:    traits.Email,
			FullName: traits.FullName,
			Role:     traits.Role,
		}

		return appDB.Create(profile).Error
	})

	// 5. Simulate Registration
	fmt.Println("--- REGISTRATION PHASE ---")
	fmt.Println("Registering user 'John Doe'...")
	userTraits := identity.JSON(`{"email": "john@example.com", "full_name": "John Doe", "role": "admin"}`)

	ident, err := regManager.Submit(context.Background(), "password", userTraits, "secure-password123")
	if err != nil {
		log.Fatalf("Registration failed: %v", err)
	}
	fmt.Printf("✓ Success! Identity created: %s\n", ident.ID)

	// 6. Verify Registration (Approach 1: Companion Profile)
	var profile UserProfile
	appDB.First(&profile, "id = ?", ident.ID)
	fmt.Printf("Retrieved from UserProfile Table: Name=%s, Role=%s\n", profile.FullName, profile.Role)

	// 7. Simulate Login
	fmt.Println("\n--- LOGIN PHASE ---")
	fmt.Println("Attempting login...")
	loggedInIdent, err := loginManager.Authenticate(context.Background(), "password", "john@example.com", "secure-password123")
	if err != nil {
		log.Fatalf("Login failed: %v", err)
	}
	fmt.Printf("✓ Login Success for: %s\n", loggedInIdent.ID)

	// 8. Access dynamic profile data during or after login
	var loginProfile UserProfile
	appDB.First(&loginProfile, "id = ?", loggedInIdent.ID)
	fmt.Printf("Parsed user role from profile table: %s\n", loginProfile.Role)
}
