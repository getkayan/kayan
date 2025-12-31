package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"

	"github.com/getkayan/kayan/flow"
	"github.com/getkayan/kayan/identity"
	"github.com/getkayan/kayan/persistence"
	"github.com/glebarez/sqlite"
	"github.com/google/uuid"
	"gorm.io/gorm"
)

// =============================================================================
// CUSTOM STORAGE MAPPING PATTERN
// Implement the IdentityStorage interface to map Kayan Identity to your DB.
// =============================================================================

type LegacyUser struct {
	ID    string `gorm:"primaryKey"`
	Email string
	Name  string
}

// CustomIdentityStorage wraps a standard repository but overrides CreateIdentity
type CustomIdentityStorage struct {
	*persistence.Repository[uuid.UUID]
	db *gorm.DB
}

func (s *CustomIdentityStorage) CreateIdentity(ident *identity.Identity[uuid.UUID]) error {
	fmt.Printf("[Storage] Custom mapping logic for identity: %s\n", ident.ID)

	// 1. Save standard Kayan Identity (Auth/Creds)
	if err := s.Repository.CreateIdentity(ident); err != nil {
		return err
	}

	// 2. Map to a specific 'LegacyUser' table simultaneously
	var traits struct {
		Email string `json:"email"`
		Name  string `json:"full_name"`
	}
	json.Unmarshal(ident.Traits, &traits)

	return s.db.Create(&LegacyUser{
		ID:    ident.ID.String(),
		Email: traits.Email,
		Name:  traits.Name,
	}).Error
}

func main() {
	// 1. Setup DB
	db, _ := gorm.Open(sqlite.Open("custom_mapping.db"), &gorm.Config{})
	db.AutoMigrate(&LegacyUser{})

	// 2. Setup Kayan Storage with our Custom Wrapper
	// persistence.NewStorage returns a Storage[T].
	baseRepo, err := persistence.NewStorage[uuid.UUID]("sqlite", "kayan_auth_custom.db", nil)
	if err != nil {
		log.Fatalf("failed to initialize Kayan storage: %v", err)
	}

	// type assertion to get the gorm-based Repository
	gormRepo := baseRepo.(*persistence.Repository[uuid.UUID])

	customStorage := &CustomIdentityStorage{
		Repository: gormRepo,
		db:         db,
	}

	// 3. Register a User
	regManager := flow.NewRegistrationManager[uuid.UUID](customStorage)
	loginManager := flow.NewLoginManager[uuid.UUID](customStorage)
	hasher := flow.NewBcryptHasher(14)
	pwStrategy := flow.NewPasswordStrategy[uuid.UUID](customStorage, hasher, "email")

	// Configure ID generation for UUIDs
	pwStrategy.SetIDGenerator(uuid.New)

	regManager.RegisterStrategy(pwStrategy)
	loginManager.RegisterStrategy(pwStrategy)

	fmt.Println("--- REGISTRATION PHASE ---")
	fmt.Println("Registering user to custom mapped storage...")
	traits := identity.JSON(`{"email": "mapped@example.com", "full_name": "Mapped User"}`)
	ident, _ := regManager.Submit(context.Background(), "password", traits, "password123")
	fmt.Printf("✓ Registered Identity: %s\n", ident.ID)

	// 4. Verify Registration
	var legacy LegacyUser
	db.First(&legacy, "id = ?", ident.ID.String())
	fmt.Printf("Retrieved from LegacyUser table: Name=%s, Email=%s\n", legacy.Name, legacy.Email)

	// 5. Login
	fmt.Println("\n--- LOGIN PHASE ---")
	fmt.Println("Attempting login...")
	loggedInIdent, err := loginManager.Authenticate(context.Background(), "password", "mapped@example.com", "password123")
	if err != nil {
		log.Fatalf("Login failed: %v", err)
	}
	fmt.Printf("✓ Login Success for: %s\n", loggedInIdent.ID)

	// Verify legacy data after login
	var loginLegacy LegacyUser
	db.First(&loginLegacy, "id = ?", loggedInIdent.ID.String())
	fmt.Printf("Successfully mapped to legacy name after login: %s\n", loginLegacy.Name)
}
