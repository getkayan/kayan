package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"time"

	"github.com/getkayan/kayan/flow"
	"github.com/getkayan/kayan/identity"
	"github.com/glebarez/sqlite"
	"github.com/google/uuid"
	"gorm.io/gorm"
)

// =============================================================================
// THE DEVELOPER'S LEGACY / CUSTOM SCHEMA
// None of these tables match Kayan's default naming or structure.
// =============================================================================

type MyAccount struct {
	UID       string `gorm:"primaryKey"` // Maps to identity.ID
	EmailAddr string `gorm:"uniqueIndex"`
	FullName  string
	PassHash  string // We store the secret directly in the account table
	CreatedAt time.Time
}

type MySession struct {
	SessionID string `gorm:"primaryKey"`
	OwnerUID  string
	Locked    bool
	Expiry    time.Time
}

// =============================================================================
// THE ADAPTER (Full Custom Storage)
// This implements domain.Storage by mapping everything to MyAccount/MySession.
// =============================================================================

type FullCustomStorage struct {
	db *gorm.DB
}

// --- Identity & Credential Storage ---

func (s *FullCustomStorage) CreateIdentity(ident *identity.Identity[string]) error {
	fmt.Printf("[Adapter] Creating custom account for: %s\n", ident.ID)

	// Extract data from Kayan's Identity struct
	var traits struct {
		Email string `json:"email"`
		Name  string `json:"full_name"`
	}
	json.Unmarshal(ident.Traits, &traits)

	// Kayan puts credentials in the '.Credentials' slice if using default strategies
	var secret string
	if len(ident.Credentials) > 0 {
		secret = ident.Credentials[0].Secret
	}

	// Save to our completely custom table
	return s.db.Create(&MyAccount{
		UID:       ident.ID,
		EmailAddr: traits.Email,
		FullName:  traits.Name,
		PassHash:  secret,
		CreatedAt: time.Now(),
	}).Error
}

func (s *FullCustomStorage) GetIdentity(id string) (*identity.Identity[string], error) {
	var acc MyAccount
	if err := s.db.First(&acc, "uid = ?", id).Error; err != nil {
		return nil, err
	}

	// Map BACK to Kayan's Identity struct
	traits, _ := json.Marshal(map[string]string{
		"email":     acc.EmailAddr,
		"full_name": acc.FullName,
	})

	return &identity.Identity[string]{
		ID:     acc.UID,
		Traits: identity.JSON(traits),
	}, nil
}

func (s *FullCustomStorage) GetCredentialByIdentifier(identifier, method string) (*identity.Credential[string], error) {
	fmt.Printf("[Adapter] Looking up credential: %s\n", identifier)

	var acc MyAccount
	if err := s.db.First(&acc, "email_addr = ?", identifier).Error; err != nil {
		return nil, err
	}

	// Map our account table record back to a Kayan Credential struct
	return &identity.Credential[string]{
		IdentityID: acc.UID,
		Identifier: acc.EmailAddr,
		Secret:     acc.PassHash,
		Type:       "password", // method
	}, nil
}

// --- Session Storage ---

func (s *FullCustomStorage) CreateSession(sess *identity.Session[string]) error {
	return s.db.Create(&MySession{
		SessionID: sess.ID,
		OwnerUID:  sess.IdentityID,
		Expiry:    sess.ExpiresAt,
		Locked:    !sess.Active,
	}).Error
}

func (s *FullCustomStorage) GetSession(id string) (*identity.Session[string], error) {
	var ms MySession
	if err := s.db.First(&ms, "session_id = ?", id).Error; err != nil {
		return nil, err
	}

	return &identity.Session[string]{
		ID:         ms.SessionID,
		IdentityID: ms.OwnerUID,
		ExpiresAt:  ms.Expiry,
		Active:     !ms.Locked,
	}, nil
}

func (s *FullCustomStorage) DeleteSession(id string) error {
	return s.db.Delete(&MySession{}, "session_id = ?", id).Error
}

func main() {
	// 1. Setup DB with CGO-free driver
	db, _ := gorm.Open(sqlite.Open("full_custom.db"), &gorm.Config{})
	db.AutoMigrate(&MyAccount{}, &MySession{})

	// 2. Wrap our DB in the FullCustomStorage adapter
	storage := &FullCustomStorage{db: db}

	// 3. Setup Kayan Managers
	regManager := flow.NewRegistrationManager[string](storage)
	loginManager := flow.NewLoginManager[string](storage)

	hasher := flow.NewBcryptHasher(14)
	pwStrategy := flow.NewPasswordStrategy[string](storage, hasher, "email")

	// Configure ID generation for string IDs
	pwStrategy.SetIDGenerator(func() string {
		return uuid.New().String()
	})

	regManager.RegisterStrategy(pwStrategy)
	loginManager.RegisterStrategy(pwStrategy)

	// --- DEMONSTRATION ---

	fmt.Println("--- REGISTRATION ---")
	traits := identity.JSON(`{"email": "custom@logic.com", "full_name": "Full Custom"}`)
	ident, err := regManager.Submit(context.Background(), "password", traits, "secret-pass")
	if err != nil {
		log.Fatalf("Reg failed: %v", err)
	}
	fmt.Printf("✓ User saved to 'MyAccount' table. ID: %s\n", ident.ID)

	fmt.Println("\n--- LOGIN ---")
	loggedIn, err := loginManager.Authenticate(context.Background(), "password", "custom@logic.com", "secret-pass")
	if err != nil {
		log.Fatalf("Login failed: %v", err)
	}
	fmt.Printf("✓ Login successful for UID: %s\n", loggedIn.ID)

	// Clean up
	fmt.Println("\n(Cleaning up databases...)")
}
