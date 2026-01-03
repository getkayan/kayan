package main

import (
	"fmt"
	"log"
	"time"

	"github.com/getkayan/kayan/session"
)

func main() {
	// 1. Initialize the JWTStrategy
	// This strategy is stateless and does not require a database repository.
	// It only needs a secret key for signing and an expiry duration.
	secret := "your-very-secure-secret-key"
	expiry := 1 * time.Hour
	jwtStrategy := session.NewHS256Strategy(secret, expiry)

	// 2. Initialize the Session Manager with the strategy
	manager := session.NewManager(jwtStrategy)

	// 3. Create a session (signs a JWT)
	// For JWT strategy, the sessionID passed to Create is typically stored in the 'sid' claim.
	sessionID := "internal_sess_id_789"
	identityID := "user_abc"
	sess, err := manager.Create(sessionID, identityID)
	if err != nil {
		log.Fatalf("Failed to create JWT: %v", err)
	}

	fmt.Printf("Created JWT Session:\n")
	fmt.Printf("  Token (Session ID): %s...\n", sess.ID[:20]) // Only show part of the token
	fmt.Printf("  Identity ID: %s\n", sess.IdentityID)
	fmt.Printf("  Expires At: %v\n", sess.ExpiresAt)

	// 4. Validate the session (parses and verifies the JWT)
	// You pass the token (sess.ID) to Validate.
	validatedSess, err := manager.Validate(sess.ID)
	if err != nil {
		log.Fatalf("Failed to validate JWT: %v", err)
	}

	fmt.Printf("\nValidated JWT Session:\n")
	fmt.Printf("  Identity ID from token: %s (Match: %v)\n", validatedSess.IdentityID, validatedSess.IdentityID == identityID)

	// 5. Delete is a no-op for stateless JWTs
	err = manager.Delete(sess.ID)
	if err != nil {
		log.Fatalf("Delete failed: %v", err)
	}
	fmt.Printf("\nStateless session 'delete' called (no-op).\n")

	// 6. Token is still valid until it naturally expires
	validatedSess, err = manager.Validate(sess.ID)
	if err == nil {
		fmt.Printf("Token is still valid (stateless): %s\n", validatedSess.IdentityID)
	} else {
		log.Fatalf("Unexpected validation failure: %v", err)
	}
}
