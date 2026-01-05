package session

import (
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"testing"
	"time"

	"github.com/getkayan/kayan/core/identity"
	"github.com/golang-jwt/jwt/v5"
)

type mockStorage struct {
	sessions map[string]*identity.Session
}

func (m *mockStorage) CreateSession(s *identity.Session) error {
	m.sessions[s.ID] = s
	return nil
}
func (m *mockStorage) GetSession(id any) (*identity.Session, error) {
	s, ok := m.sessions[fmt.Sprintf("%v", id)]
	if !ok {
		return nil, fmt.Errorf("not found")
	}
	return s, nil
}
func (m *mockStorage) GetSessionByRefreshToken(token string) (*identity.Session, error) {
	for _, s := range m.sessions {
		if s.RefreshToken == token {
			return s, nil
		}
	}
	return nil, fmt.Errorf("not found")
}
func (m *mockStorage) DeleteSession(id any) error {
	delete(m.sessions, fmt.Sprintf("%v", id))
	return nil
}

func TestDatabaseStrategy(t *testing.T) {
	storage := &mockStorage{sessions: make(map[string]*identity.Session)}
	strategy := NewDatabaseStrategy(storage)
	manager := NewManager(strategy)

	// Test Create
	sess, err := manager.Create("test-session", "test-user")
	if err != nil {
		t.Fatalf("failed to create session: %v", err)
	}
	if sess.ID != "test-session" {
		t.Errorf("expected session ID test-session, got %v", sess.ID)
	}
	if sess.RefreshToken == "" {
		t.Error("expected refresh token to be generated")
	}

	// Test Validate
	sess, err = manager.Validate(sess.ID)
	if err != nil {
		t.Fatalf("failed to validate session: %v", err)
	}

	// Test Refresh (Rotation)
	oldID := sess.ID
	oldRT := sess.RefreshToken
	newSess, err := manager.Refresh(oldRT)
	if err != nil {
		t.Fatalf("failed to refresh session: %v", err)
	}

	if newSess.ID == oldID {
		t.Error("expected session ID to rotate")
	}
	if newSess.RefreshToken == oldRT {
		t.Error("expected refresh token to rotate")
	}

	// Old session should be deleted
	_, err = manager.Validate(oldID)
	if err == nil {
		t.Error("expected old session to be deleted after rotation")
	}
}

func TestJWTStrategy(t *testing.T) {
	secret := "my-secret-key"
	strategy := NewHS256Strategy(secret, time.Hour)
	manager := NewManager(strategy)

	// Test Create
	sess, err := manager.Create("test-session", "test-user")
	if err != nil {
		t.Fatalf("failed to create JWT session: %v", err)
	}
	if sess.RefreshToken == "" {
		t.Error("expected refresh token to be generated for JWT")
	}

	// Test Refresh
	newSess, err := manager.Refresh(sess.RefreshToken)
	if err != nil {
		t.Fatalf("failed to refresh JWT: %v", err)
	}
	if newSess.ID == sess.ID {
		t.Error("expected JWT access token to rotate")
	}
}
func TestJWTRSAStrategy(t *testing.T) {
	// Generate RSA keys
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate RSA key: %v", err)
	}
	publicKey := &privateKey.PublicKey

	strategy := NewJWTStrategy(JWTConfig{
		SigningMethod: jwt.SigningMethodRS256,
		SigningKey:    privateKey,
		VerifyingKey:  publicKey,
		Expiry:        time.Hour,
	})
	manager := NewManager(strategy)

	// Test Create
	sess, err := manager.Create("test-session", "test-user")
	if err != nil {
		t.Fatalf("failed to create RSA JWT: %v", err)
	}

	// Test Validate
	validatedSess, err := manager.Validate(sess.ID)
	if err != nil {
		t.Fatalf("failed to validate RSA JWT: %v", err)
	}
	if validatedSess.IdentityID != "test-user" {
		t.Errorf("expected identity ID test-user, got %v", validatedSess.IdentityID)
	}
}
