package main

import (
	"fmt"
	"log"
	"time"

	"github.com/getkayan/kayan/identity"
	"github.com/getkayan/kayan/session"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

// MapStorage is a simple non-GORM storage implementation
type MapStorage struct {
	sessions map[string]*identity.Session
}

func (m *MapStorage) CreateSession(s *identity.Session) error {
	m.sessions[s.ID] = s
	return nil
}
func (m *MapStorage) GetSession(id any) (*identity.Session, error) {
	s, ok := m.sessions[fmt.Sprintf("%v", id)]
	if !ok {
		return nil, fmt.Errorf("session not found")
	}
	return s, nil
}
func (m *MapStorage) GetSessionByRefreshToken(token string) (*identity.Session, error) {
	for _, s := range m.sessions {
		if s.RefreshToken == token {
			return s, nil
		}
	}
	return nil, fmt.Errorf("refresh token not found")
}
func (m *MapStorage) DeleteSession(id any) error {
	delete(m.sessions, fmt.Sprintf("%v", id))
	return nil
}

func main() {
	storage := &MapStorage{sessions: make(map[string]*identity.Session)}

	// 1. Database Strategy with Custom Hook
	// Developers can fully override the rotation logic if they want.
	dbStrategy := session.NewDatabaseStrategy(storage)
	dbStrategy.RefreshHook = func(refreshToken string) (*identity.Session, error) {
		fmt.Printf("[Hook] Custom rotation logic triggered for token: %s\n", refreshToken)
		// Custom logic: find, validate, and return
		sess, err := storage.GetSessionByRefreshToken(refreshToken)
		if err != nil {
			return nil, err
		}
		// Perform custom rotation
		sess.ID = "hooked_" + uuid.New().String()
		sess.RefreshToken = "hooked_rt_" + uuid.New().String()
		storage.CreateSession(sess)
		return sess, nil
	}

	manager := session.NewManager(dbStrategy)

	// Create session
	sess, _ := manager.Create("initial_id", "user_1")
	fmt.Printf("Initial Session: ID=%s, RT=%s\n", sess.ID, sess.RefreshToken)

	// Refresh (triggers hook)
	refreshed, err := manager.Refresh(sess.RefreshToken)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("Refreshed Session: ID=%s, RT=%s\n", refreshed.ID, refreshed.RefreshToken)

	// 2. JWT Strategy with Dual Tokens and Blacklist Validator
	// Use HS256 for both AT and RT for simplicity in this example
	jwtStrategy := session.NewHS256Strategy("secret", 15*time.Minute)

	// Custom Validator Hook: Check if RT is blacklisted
	blacklist := map[string]bool{"blacklisted_token": true}
	jwtStrategy.SetRefreshTokenValidator(func(token *jwt.Token) error {
		raw := token.Raw
		if blacklist[raw] {
			return fmt.Errorf("token is blacklisted")
		}
		fmt.Println("[Hook] JWT Refresh Token validated successfully")
		return nil
	})

	jwtManager := session.NewManager(jwtStrategy)

	// Create JWT session
	jwtSess, _ := jwtManager.Create("sid_123", "user_abc")
	fmt.Printf("\nJWT Session Created:\n  Access Token: %s...\n  Refresh Token: %s...\n",
		jwtSess.ID[:10], jwtSess.RefreshToken[:10])

	// Refresh JWT
	newJwtSess, err := jwtManager.Refresh(jwtSess.RefreshToken)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("JWT Refreshed: New AT starts with %s...\n", newJwtSess.ID[:10])
}
