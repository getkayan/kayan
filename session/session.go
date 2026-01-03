package session

import (
	"fmt"
	"time"

	"github.com/getkayan/kayan/domain"
	"github.com/getkayan/kayan/identity"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

type Session = identity.Session

// Strategy defines the interface for session management strategies.
type Strategy interface {
	Create(sessionID, identityID any) (*identity.Session, error)
	Validate(sessionID any) (*identity.Session, error)
	Refresh(refreshToken string) (*identity.Session, error)
	Delete(sessionID any) error
}

// DatabaseStrategy implements the session strategy using a database.
type DatabaseStrategy struct {
	repo        domain.SessionStorage
	RefreshHook func(refreshToken string) (*identity.Session, error)
}

func NewDatabaseStrategy(repo domain.SessionStorage) *DatabaseStrategy {
	return &DatabaseStrategy{repo: repo}
}

func (s *DatabaseStrategy) Create(sessionID, identityID any) (*identity.Session, error) {
	sess := NewSession(sessionID, identityID)
	// Default refresh token strategy for database
	sess.RefreshToken = uuid.New().String()
	sess.RefreshExpiresAt = time.Now().Add(7 * 24 * time.Hour)

	if err := s.repo.CreateSession(sess); err != nil {
		return nil, err
	}
	return sess, nil
}

func (s *DatabaseStrategy) Validate(sessionID any) (*identity.Session, error) {
	sess, err := s.repo.GetSession(sessionID)
	if err != nil {
		return nil, err
	}

	if !sess.Active || sess.ExpiresAt.Before(time.Now()) {
		return nil, fmt.Errorf("session expired or inactive")
	}

	return sess, nil
}

func (s *DatabaseStrategy) Refresh(refreshToken string) (*identity.Session, error) {
	if s.RefreshHook != nil {
		return s.RefreshHook(refreshToken)
	}

	// Default rotation logic
	sess, err := s.repo.GetSessionByRefreshToken(refreshToken)
	if err != nil {
		return nil, fmt.Errorf("invalid refresh token")
	}

	if !sess.Active || sess.RefreshExpiresAt.Before(time.Now()) {
		return nil, fmt.Errorf("refresh token expired or inactive")
	}

	// Rotate: Issue new Session ID and new Refresh Token
	// This is a robust default that prevents replay attacks
	oldID := sess.ID
	sess.ID = uuid.New().String()
	sess.RefreshToken = uuid.New().String()
	sess.IssuedAt = time.Now()
	sess.ExpiresAt = time.Now().Add(24 * time.Hour)
	sess.RefreshExpiresAt = time.Now().Add(7 * 24 * time.Hour)

	if err := s.repo.CreateSession(sess); err != nil {
		return nil, err
	}

	// Invalidate old session
	_ = s.repo.DeleteSession(oldID)

	return sess, nil
}

func (s *DatabaseStrategy) Delete(sessionID any) error {
	return s.repo.DeleteSession(sessionID)
}

// JWTConfig holds the configuration for JWT-based sessions.
type JWTConfig struct {
	SigningMethod jwt.SigningMethod
	SigningKey    any // e.g., []byte for HMAC, *rsa.PrivateKey for RSA
	VerifyingKey  any // e.g., []byte for HMAC (same as SigningKey), *rsa.PublicKey for RSA
	Expiry        time.Duration

	// Token Rotation
	RefreshSigningMethod  jwt.SigningMethod
	RefreshSigningKey     any
	RefreshVerifyingKey   any
	RefreshExpiry         time.Duration
	RefreshTokenValidator func(token *jwt.Token) error
}

// JWTStrategy implements the session strategy using JSON Web Tokens.
type JWTStrategy struct {
	config JWTConfig
}

// NewJWTStrategy creates a new JWT strategy with the given configuration.
func NewJWTStrategy(config JWTConfig) *JWTStrategy {
	return &JWTStrategy{config: config}
}

// SetRefreshTokenValidator sets a custom validator for refresh tokens.
func (s *JWTStrategy) SetRefreshTokenValidator(v func(token *jwt.Token) error) {
	s.config.RefreshTokenValidator = v
}

// NewHS256Strategy is a convenience constructor for HS256 strategy.
func NewHS256Strategy(secret string, expiry time.Duration) *JWTStrategy {
	return &JWTStrategy{
		config: JWTConfig{
			SigningMethod:        jwt.SigningMethodHS256,
			SigningKey:           []byte(secret),
			VerifyingKey:         []byte(secret),
			Expiry:               expiry,
			RefreshSigningMethod: jwt.SigningMethodHS256,
			RefreshSigningKey:    []byte(secret),
			RefreshVerifyingKey:  []byte(secret),
			RefreshExpiry:        7 * 24 * time.Hour,
		},
	}
}

// JWTClaims represents the data stored in the JWT.
type JWTClaims struct {
	SessionID string `json:"sid"`
	jwt.RegisteredClaims
}

func (s *JWTStrategy) Create(sessionID, identityID any) (*identity.Session, error) {
	now := time.Now()

	// Access Token
	atExpiresAt := now.Add(s.config.Expiry)
	atClaims := JWTClaims{
		SessionID: fmt.Sprintf("%v", sessionID),
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   fmt.Sprintf("%v", identityID),
			ExpiresAt: jwt.NewNumericDate(atExpiresAt),
			IssuedAt:  jwt.NewNumericDate(now),
		},
	}
	atToken := jwt.NewWithClaims(s.config.SigningMethod, atClaims)
	atString, err := atToken.SignedString(s.config.SigningKey)
	if err != nil {
		return nil, err
	}

	// Refresh Token
	rtExpiresAt := now.Add(s.config.RefreshExpiry)
	rtClaims := JWTClaims{
		SessionID: fmt.Sprintf("%v", sessionID),
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   fmt.Sprintf("%v", identityID),
			ExpiresAt: jwt.NewNumericDate(rtExpiresAt),
			IssuedAt:  jwt.NewNumericDate(now),
		},
	}
	rtMethod := s.config.RefreshSigningMethod
	if rtMethod == nil {
		rtMethod = s.config.SigningMethod
	}
	rtKey := s.config.RefreshSigningKey
	if rtKey == nil {
		rtKey = s.config.SigningKey
	}
	rtToken := jwt.NewWithClaims(rtMethod, rtClaims)
	rtString, err := rtToken.SignedString(rtKey)
	if err != nil {
		return nil, err
	}

	return &identity.Session{
		ID:               atString,
		IdentityID:       fmt.Sprintf("%v", identityID),
		RefreshToken:     rtString,
		ExpiresAt:        atExpiresAt,
		RefreshExpiresAt: rtExpiresAt,
		IssuedAt:         now,
		Active:           true,
	}, nil
}

func (s *JWTStrategy) Validate(sessionID any) (*identity.Session, error) {
	tokenString, ok := sessionID.(string)
	if !ok {
		return nil, fmt.Errorf("invalid token format")
	}

	token, err := jwt.ParseWithClaims(tokenString, &JWTClaims{}, func(token *jwt.Token) (interface{}, error) {
		// Verify method algorithm matches config
		if token.Method.Alg() != s.config.SigningMethod.Alg() {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return s.config.VerifyingKey, nil
	})

	if err != nil {
		return nil, err
	}

	if claims, ok := token.Claims.(*JWTClaims); ok && token.Valid {
		return &identity.Session{
			ID:         tokenString,
			IdentityID: claims.Subject,
			ExpiresAt:  claims.ExpiresAt.Time,
			IssuedAt:   claims.IssuedAt.Time,
			Active:     true,
		}, nil
	}

	return nil, fmt.Errorf("invalid token")
}

func (s *JWTStrategy) Refresh(refreshToken string) (*identity.Session, error) {
	rtMethod := s.config.RefreshSigningMethod
	if rtMethod == nil {
		rtMethod = s.config.SigningMethod
	}
	rtKey := s.config.RefreshVerifyingKey
	if rtKey == nil {
		rtKey = s.config.VerifyingKey
	}

	token, err := jwt.ParseWithClaims(refreshToken, &JWTClaims{}, func(token *jwt.Token) (interface{}, error) {
		if token.Method.Alg() != rtMethod.Alg() {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return rtKey, nil
	})

	if err != nil {
		return nil, err
	}

	if s.config.RefreshTokenValidator != nil {
		if err := s.config.RefreshTokenValidator(token); err != nil {
			return nil, err
		}
	}

	if claims, ok := token.Claims.(*JWTClaims); ok && token.Valid {
		// Issue new AT and new RT (Rotation)
		newSessionID := uuid.New().String()
		return s.Create(newSessionID, claims.Subject)
	}

	return nil, fmt.Errorf("invalid refresh token")
}

func (s *JWTStrategy) Delete(sessionID any) error {
	// Stateless, nothing to delete on server side.
	return nil
}

func NewSession(sessionID, identityID any) *identity.Session {
	return &identity.Session{
		ID:         fmt.Sprintf("%v", sessionID),
		IdentityID: fmt.Sprintf("%v", identityID),
		ExpiresAt:  time.Now().Add(24 * time.Hour),
		IssuedAt:   time.Now(),
		Active:     true,
	}
}
