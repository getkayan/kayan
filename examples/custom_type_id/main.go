package main

import (
	"context"
	"database/sql/driver"
	"fmt"
	"log"
	"os"
	"strconv"

	"github.com/getkayan/kayan/api"
	"github.com/getkayan/kayan/flow"
	"github.com/getkayan/kayan/identity"
	"github.com/getkayan/kayan/persistence"
	"github.com/getkayan/kayan/session"
)

// CustomID is a user-defined type that wraps a primitive.
// It implements sql.Scanner and driver.Valuer for GORM compatibility.
type CustomID struct {
	Val uint16
}

// Valuer interface: how to store it in the DB
func (c CustomID) Value() (driver.Value, error) {
	return int64(c.Val), nil
}

// Scanner interface: how to read it from the DB
func (c *CustomID) Scan(value interface{}) error {
	if value == nil {
		c.Val = 0
		return nil
	}

	switch v := value.(type) {
	case int64:
		c.Val = uint16(v)
	case uint64:
		c.Val = uint16(v)
	case []byte:
		i, _ := strconv.ParseUint(string(v), 10, 16)
		c.Val = uint16(i)
	default:
		return fmt.Errorf("cannot scan %T into CustomID", value)
	}
	return nil
}

// String representation for logging and API tokens
func (c CustomID) String() string {
	return strconv.FormatUint(uint64(c.Val), 10)
}

// ParseCustomID converts a string token back to CustomID
func ParseCustomID(s string) (CustomID, error) {
	v, err := strconv.ParseUint(s, 10, 16)
	if err != nil {
		return CustomID{}, err
	}
	return CustomID{Val: uint16(v)}, nil
}

func main() {
	dbPath := "custom_ids.db"
	os.Remove(dbPath) // Clean up any leftover from previous failed runs
	defer os.Remove(dbPath)

	// 1. Initialize Storage with CustomID
	storage, err := persistence.NewStorage[CustomID]("sqlite", dbPath, nil)
	if err != nil {
		log.Fatalf("failed to initialize storage: %v", err)
	}

	// 2. Setup Managers
	regManager := flow.NewRegistrationManager(storage)
	loginManager := flow.NewLoginManager(storage)
	sessionManager := session.NewManager(storage)

	// 3. Setup Strategy with ID Generator
	hasher := flow.NewBcryptHasher(14)
	pwStrategy := flow.NewPasswordStrategy[CustomID](storage, hasher, "email")

	var nextID uint16 = 1000
	pwStrategy.SetIDGenerator(func() CustomID {
		id := CustomID{Val: nextID}
		nextID++
		return id
	})

	regManager.RegisterStrategy(pwStrategy)
	loginManager.RegisterStrategy(pwStrategy)

	// 4. DEMONSTRATION: Registration
	fmt.Println("--- REGISTRATION ---")
	traits := identity.JSON(`{"email": "custom@example.com"}`)
	ident, err := regManager.Submit(context.Background(), "password", traits, "secure-pass")
	if err != nil {
		log.Fatalf("registration failed: %v", err)
	}
	fmt.Printf("✓ Registered Identity with CustomID: %s (wrapped uint16: %d)\n", ident.ID, ident.ID.Val)

	// 5. DEMONSTRATION: Login & Session
	fmt.Println("\n--- LOGIN & SESSION ---")
	loggedIn, err := loginManager.Authenticate(context.Background(), "password", "custom@example.com", "secure-pass")
	if err != nil {
		log.Fatalf("login failed: %v", err)
	}

	// Create a session with a custom ID
	sid := CustomID{Val: 555}
	sess, err := sessionManager.Create(sid, loggedIn.ID)
	if err != nil {
		log.Fatalf("session creation failed: %v", err)
	}
	fmt.Printf("✓ Created Session %s for Identity %s\n", sess.ID, sess.IdentityID)

	// 6. DEMONSTRATION: API Handler (Token Parsing)
	fmt.Println("\n--- API HANDLER (TOKEN VALIDATION) ---")
	handler := api.NewHandler(regManager, loginManager, sessionManager, nil)

	// Setup the token parser for our custom type
	handler.SetTokenParser(func(token string) (CustomID, error) {
		return ParseCustomID(token)
	})

	// Simulate a token from a header
	tokenStr := sess.ID.String()
	fmt.Printf("Simulating request with Authorization token: %s\n", tokenStr)

	validatedSess, err := sessionManager.Validate(sess.ID)
	if err != nil {
		log.Fatalf("validation failed: %v", err)
	}
	fmt.Printf("✓ Validated session! Identity ID is: %s\n", validatedSess.IdentityID)

	fmt.Println("\nSUCCESS: Custom ID type handled correctly by GORM and Kayan components.")
}
