package main

import (
	"fmt"
	"log"

	"github.com/getkayan/kayan/identity"
	"github.com/getkayan/kayan/session"
)

// InMemorySessionRepo is a simple in-memory implementation of domain.SessionStorage
type InMemorySessionRepo struct {
	sessions map[string]*identity.Session
}

func (r *InMemorySessionRepo) CreateSession(s *identity.Session) error {
	r.sessions[s.ID] = s
	return nil
}

func (r *InMemorySessionRepo) GetSession(id any) (*identity.Session, error) {
	s, ok := r.sessions[fmt.Sprintf("%v", id)]
	if !ok {
		return nil, fmt.Errorf("session not found")
	}
	return s, nil
}

func (r *InMemorySessionRepo) GetSessionByRefreshToken(token string) (*identity.Session, error) {
	for _, s := range r.sessions {
		if s.RefreshToken == token {
			return s, nil
		}
	}
	return nil, fmt.Errorf("session not found")
}

func (r *InMemorySessionRepo) DeleteSession(id any) error {
	delete(r.sessions, fmt.Sprintf("%v", id))
	return nil
}

func main() {
	// 1. Initialize the repository
	repo := &InMemorySessionRepo{
		sessions: make(map[string]*identity.Session),
	}

	// 2. Create the DatabaseStrategy
	// This strategy uses the repository to store and retrieve sessions.
	dbStrategy := session.NewDatabaseStrategy(repo)

	// 3. Initialize the Session Manager with the strategy
	manager := session.NewManager(dbStrategy)

	// 4. Create a session
	sessionID := "sess_123"
	identityID := "user_456"
	sess, err := manager.Create(sessionID, identityID)
	if err != nil {
		log.Fatalf("Failed to create session: %v", err)
	}

	fmt.Printf("Created Database Session:\n")
	fmt.Printf("  ID: %s\n", sess.ID)
	fmt.Printf("  Identity ID: %s\n", sess.IdentityID)
	fmt.Printf("  Expires At: %v\n", sess.ExpiresAt)

	// 5. Validate the session
	validatedSess, err := manager.Validate(sess.ID)
	if err != nil {
		log.Fatalf("Failed to validate session: %v", err)
	}

	fmt.Printf("\nValidated Session:\n")
	fmt.Printf("  Identity ID: %s (Match: %v)\n", validatedSess.IdentityID, validatedSess.IdentityID == identityID)

	// 6. Delete the session
	err = manager.Delete(sess.ID)
	if err != nil {
		log.Fatalf("Failed to delete session: %v", err)
	}
	fmt.Printf("\nSession deleted successfully.\n")

	// 7. Try to validate again (should fail)
	_, err = manager.Validate(sess.ID)
	if err != nil {
		fmt.Printf("Validation failed as expected after deletion: %v\n", err)
	}
}
