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

func (s *FullCustomStorage) CreateIdentity(ident any) error {
	i := ident.(*identity.Identity)
	fmt.Printf("[Adapter] Creating custom account for: %s\n", i.ID)

	// Extract data from Kayan's Identity struct
	var traits struct {
		Email string `json:"email"`
		Name  string `json:"full_name"`
	}
	json.Unmarshal(i.Traits, &traits)

	// Kayan puts credentials in the '.Credentials' slice if using default strategies
	var secret string
	if len(i.Credentials) > 0 {
		secret = i.Credentials[0].Secret
	}

	// Save to our completely custom table
	return s.db.Create(&MyAccount{
		UID:       i.ID,
		EmailAddr: traits.Email,
		FullName:  traits.Name,
		PassHash:  secret,
		CreatedAt: time.Now(),
	}).Error
}

func (s *FullCustomStorage) GetIdentity(factory func() any, id any) (any, error) {
	fmt.Printf("[Adapter] Getting identity: %v\n", id)
	var acc MyAccount
	if err := s.db.First(&acc, "uid = ?", id).Error; err != nil {
		return nil, err
	}

	// Map BACK to Kayan's Identity struct
	traits, _ := json.Marshal(map[string]string{
		"email":     acc.EmailAddr,
		"full_name": acc.FullName,
	})

	ident := factory().(*identity.Identity)
	ident.ID = acc.UID
	ident.Traits = identity.JSON(traits)

	return ident, nil
}

func (s *FullCustomStorage) FindIdentity(factory func() any, query map[string]any) (any, error) {
	// Simple implementation for this example
	if email, ok := query["EmailAddr"]; ok {
		var acc MyAccount
		if err := s.db.First(&acc, "email_addr = ?", email).Error; err != nil {
			return nil, err
		}
		ident := factory().(*identity.Identity)
		ident.ID = acc.UID
		return ident, nil
	}
	return nil, fmt.Errorf("lookup not implemented for query: %v", query)
}

func (s *FullCustomStorage) GetCredentialByIdentifier(identifier, method string) (*identity.Credential, error) {
	fmt.Printf("[Adapter] Looking up credential: %s\n", identifier)

	var acc MyAccount
	if err := s.db.First(&acc, "email_addr = ?", identifier).Error; err != nil {
		return nil, err
	}

	// Map our account table record back to a Kayan Credential struct
	return &identity.Credential{
		IdentityID: acc.UID,
		Identifier: acc.EmailAddr,
		Secret:     acc.PassHash,
		Type:       "password", // method
	}, nil
}

// --- Session Storage ---

func (s *FullCustomStorage) CreateSession(sess *identity.Session) error {
	return s.db.Create(&MySession{
		SessionID: sess.ID,
		OwnerUID:  sess.IdentityID,
		Expiry:    sess.ExpiresAt,
		Locked:    !sess.Active,
	}).Error
}

func (s *FullCustomStorage) GetSession(id any) (*identity.Session, error) {
	var ms MySession
	if err := s.db.First(&ms, "session_id = ?", id).Error; err != nil {
		return nil, err
	}

	return &identity.Session{
		ID:         ms.SessionID,
		IdentityID: ms.OwnerUID,
		ExpiresAt:  ms.Expiry,
		Active:     !ms.Locked,
	}, nil
}

func (s *FullCustomStorage) GetSessionByRefreshToken(token string) (*identity.Session, error) {
	return nil, fmt.Errorf("refresh token not supported in this custom schema")
}

func (s *FullCustomStorage) DeleteSession(id any) error {
	return s.db.Delete(&MySession{}, "session_id = ?", id).Error
}

func main() {
	// 1. Setup DB with CGO-free driver
	db, _ := gorm.Open(sqlite.Open("full_custom.db"), &gorm.Config{})
	db.AutoMigrate(&MyAccount{}, &MySession{})

	// 2. Wrap our DB in the FullCustomStorage adapter
	storage := &FullCustomStorage{db: db}

	// 3. Setup Kayan Managers
	factory := func() any { return &identity.Identity{} }
	regManager := flow.NewRegistrationManager(storage, factory)
	loginManager := flow.NewLoginManager(storage)

	hasher := flow.NewBcryptHasher(14)
	pwStrategy := flow.NewPasswordStrategy(storage, hasher, "email", factory)

	// Configure ID generation for string IDs
	pwStrategy.SetIDGenerator(func() any {
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
	fmt.Printf("✓ User saved to 'MyAccount' table. ID: %s\n", ident.(*identity.Identity).ID)

	fmt.Println("\n--- LOGIN ---")
	loggedIn, err := loginManager.Authenticate(context.Background(), "password", "custom@logic.com", "secret-pass")
	if err != nil {
		log.Fatalf("Login failed: %v", err)
	}
	fmt.Printf("✓ Login successful for UID: %s\n", loggedIn.(*identity.Identity).ID)

	// Clean up
	fmt.Println("\n(Cleaning up databases...)")
}
