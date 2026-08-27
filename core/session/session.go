package session

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/getkayan/kayan/core/domain"
	"github.com/getkayan/kayan/core/identity"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

type Session = identity.Session

// Strategy defines the interface for session management strategies.
type Strategy interface {
	Create(ctx context.Context, sessionID, identityID any) (*identity.Session, error)
	Validate(ctx context.Context, sessionID any) (*identity.Session, error)
	Refresh(ctx context.Context, refreshToken string) (*identity.Session, error)
	Delete(ctx context.Context, sessionID any) error
}

// DatabaseStrategy implements the session strategy using a database.
type DatabaseStrategy struct {
	repo        domain.SessionStorage
	RefreshHook func(refreshToken string) (*identity.Session, error)
}

func NewDatabaseStrategy(repo domain.SessionStorage) *DatabaseStrategy {
	return &DatabaseStrategy{repo: repo}
}

func (s *DatabaseStrategy) Create(ctx context.Context, sessionID, identityID any) (*identity.Session, error) {
	sess := NewSession(sessionID, identityID)
	// Default refresh token strategy for database
	sess.RefreshToken = uuid.New().String()
	sess.RefreshExpiresAt = time.Now().Add(7 * 24 * time.Hour)

	if err := s.repo.CreateSession(ctx, sess); err != nil {
		return nil, err
	}
	return sess, nil
}

func (s *DatabaseStrategy) Validate(ctx context.Context, sessionID any) (*identity.Session, error) {
	sess, err := s.repo.GetSession(ctx, sessionID)
	if err != nil {
		return nil, err
	}

	if !sess.Active || sess.ExpiresAt.Before(time.Now()) {
		return nil, fmt.Errorf("session expired or inactive")
	}

	return sess, nil
}

func (s *DatabaseStrategy) Refresh(ctx context.Context, refreshToken string) (*identity.Session, error) {
	if s.RefreshHook != nil {
		return s.RefreshHook(refreshToken)
	}

	// Default rotation logic
	sess, err := s.repo.GetSessionByRefreshToken(ctx, refreshToken)
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

	if err := s.repo.CreateSession(ctx, sess); err != nil {
		return nil, err
	}

	// Invalidate old session
	_ = s.repo.DeleteSession(ctx, oldID)

	return sess, nil
}

// RevokeAll deletes every stored session belonging to an identity.
//
// Stored sessions are enumerable, so unlike the JWT strategy this removes the
// rows outright and needs no cutoff.
func (s *DatabaseStrategy) RevokeAll(ctx context.Context, identityID any) error {
	bulk, ok := s.repo.(domain.BulkSessionStorage)
	if !ok {
		return fmt.Errorf("session: the configured session storage does not implement " +
			"domain.BulkSessionStorage, so it cannot revoke every session for an identity")
	}
	return bulk.DeleteSessionsByIdentity(ctx, identityID)
}

func (s *DatabaseStrategy) Delete(ctx context.Context, sessionID any) error {
	return s.repo.DeleteSession(ctx, sessionID)
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
	config     JWTConfig
	revocation RevocationStore
}

// NewJWTStrategy creates a new JWT strategy with the given configuration.
func NewJWTStrategy(config JWTConfig) *JWTStrategy {
	return &JWTStrategy{config: config}
}

// WithRevocationStore enables distributed JWT revocation.
func (s *JWTStrategy) WithRevocationStore(store RevocationStore) *JWTStrategy {
	s.revocation = store
	return s
}

// RevocationStore persists revoked session IDs for stateless JWT invalidation.
type RevocationStore interface {
	// Revoke marks a session as revoked until its expiry.
	Revoke(ctx context.Context, sessionID string, expiresAt time.Time) error
	// IsRevoked checks whether a session is revoked.
	IsRevoked(ctx context.Context, sessionID string) (bool, error)
}

// IdentityRevocationStore revokes every session belonging to an identity.
//
// It is a separate interface so existing RevocationStore implementations keep
// compiling; a store that does not implement it cannot support RevokeAll and
// says so rather than silently doing nothing.
//
// The contract is a cutoff rather than a list of sessions. JWT sessions are
// bearer tokens the server never stored, so they cannot be enumerated to be
// deleted one by one -- but every one of them carries an issued-at claim, so a
// single timestamp per identity invalidates all of them at once and keeps
// working for tokens the store has never seen.
type IdentityRevocationStore interface {
	RevocationStore

	// RevokeIdentity records that every session issued to identityID at or
	// before cutoff is revoked.
	RevokeIdentity(ctx context.Context, identityID string, cutoff time.Time) error

	// IdentityRevokedBefore returns the cutoff for an identity, or the zero
	// time when none is recorded.
	IdentityRevokedBefore(ctx context.Context, identityID string) (time.Time, error)
}

// MemoryRevocationStore is an in-memory RevocationStore for testing/dev.
type MemoryRevocationStore struct {
	mu         sync.RWMutex
	revoked    map[string]time.Time // sessionID -> expiry
	identities map[string]time.Time // identityID -> revocation cutoff
}

func NewMemoryRevocationStore() *MemoryRevocationStore {
	return &MemoryRevocationStore{
		revoked:    make(map[string]time.Time),
		identities: make(map[string]time.Time),
	}
}

// RevokeIdentity implements [IdentityRevocationStore].
func (s *MemoryRevocationStore) RevokeIdentity(_ context.Context, identityID string, cutoff time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	// Keep the latest cutoff: a second revocation must not widen the window
	// back open for sessions the first one already ended.
	if existing, ok := s.identities[identityID]; ok && existing.After(cutoff) {
		return nil
	}
	s.identities[identityID] = cutoff
	return nil
}

// IdentityRevokedBefore implements [IdentityRevocationStore].
func (s *MemoryRevocationStore) IdentityRevokedBefore(_ context.Context, identityID string) (time.Time, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.identities[identityID], nil
}

func (s *MemoryRevocationStore) Revoke(ctx context.Context, sessionID string, expiresAt time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.revoked[sessionID] = expiresAt
	return nil
}

func (s *MemoryRevocationStore) IsRevoked(ctx context.Context, sessionID string) (bool, error) {
	s.mu.RLock()
	exp, ok := s.revoked[sessionID]
	s.mu.RUnlock()
	if !ok {
		return false, nil
	}
	if exp.Before(time.Now()) {
		s.mu.Lock()
		delete(s.revoked, sessionID)
		s.mu.Unlock()
		return false, nil
	}
	return true, nil
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

func (s *JWTStrategy) Create(ctx context.Context, sessionID, identityID any) (*identity.Session, error) {
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

// keyFunc returns a jwt.Keyfunc that accepts only tokens signed with expected.
//
// Pinning the algorithm is what stops an attacker re-signing an RS256 token as
// HS256 using the PEM of the public key as the HMAC secret: the forged token
// verifies against the public key, which is not a secret. Every parse in this
// package goes through here so the check cannot be present on some paths and
// missing on others.
func (s *JWTStrategy) keyFunc(expected jwt.SigningMethod, key any) jwt.Keyfunc {
	return func(token *jwt.Token) (any, error) {
		if expected == nil {
			return nil, fmt.Errorf("session: no signing method configured")
		}
		if token.Method.Alg() != expected.Alg() {
			return nil, fmt.Errorf("session: unexpected signing method: %v", token.Header["alg"])
		}
		return key, nil
	}
}

func (s *JWTStrategy) Validate(ctx context.Context, sessionID any) (*identity.Session, error) {
	tokenString, ok := sessionID.(string)
	if !ok {
		return nil, fmt.Errorf("invalid token format")
	}

	token, err := jwt.ParseWithClaims(tokenString, &JWTClaims{},
		s.keyFunc(s.config.SigningMethod, s.config.VerifyingKey))

	if err != nil {
		return nil, err
	}

	if claims, ok := token.Claims.(*JWTClaims); ok && token.Valid {
		// Distributed revocation check, keyed on the session rather than on
		// the token string. A session has at least two tokens -- the access
		// token and the refresh token -- and they are different strings, so
		// revoking by string ends one and leaves the other working.
		if err := s.checkRevoked(ctx, claims); err != nil {
			return nil, err
		}
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

func (s *JWTStrategy) Refresh(ctx context.Context, refreshToken string) (*identity.Session, error) {
	rtMethod := s.config.RefreshSigningMethod
	if rtMethod == nil {
		rtMethod = s.config.SigningMethod
	}
	rtKey := s.config.RefreshVerifyingKey
	if rtKey == nil {
		rtKey = s.config.VerifyingKey
	}

	token, err := jwt.ParseWithClaims(refreshToken, &JWTClaims{}, s.keyFunc(rtMethod, rtKey))

	if err != nil {
		return nil, err
	}

	if s.config.RefreshTokenValidator != nil {
		if err := s.config.RefreshTokenValidator(token); err != nil {
			return nil, err
		}
	}

	if claims, ok := token.Claims.(*JWTClaims); ok && token.Valid {
		// A revoked session must not be refreshable. Checking only in Validate
		// meant logout stopped the access token while the refresh token kept
		// minting replacements until it expired on its own.
		if err := s.checkRevoked(ctx, claims); err != nil {
			return nil, err
		}

		// Rotation: the spent session is revoked before the replacement is
		// issued, so presenting the same refresh token twice fails. Without
		// this the old token stays live alongside the new one and rotation
		// prevents nothing.
		if s.revocation != nil && claims.SessionID != "" {
			expiry := time.Now().Add(s.config.RefreshExpiry)
			if claims.ExpiresAt != nil {
				expiry = claims.ExpiresAt.Time
			}
			if err := s.revocation.Revoke(ctx, claims.SessionID, expiry); err != nil {
				return nil, fmt.Errorf("revoke spent refresh token: %w", err)
			}
		}

		newSessionID := uuid.New().String()
		return s.Create(ctx, newSessionID, claims.Subject)
	}

	return nil, fmt.Errorf("invalid refresh token")
}

func (s *JWTStrategy) Delete(ctx context.Context, sessionID any) error {
	// Distributed revocation: mark as revoked if store is present.
	if s.revocation != nil {
		tokenString, ok := sessionID.(string)
		if !ok {
			return fmt.Errorf("invalid token format")
		}
		// Parse the token to read its expiry. The algorithm is pinned here for
		// the same reason as on every other path: without it, a token forged
		// with the public key as an HMAC secret would revoke an arbitrary
		// session.
		token, err := jwt.ParseWithClaims(tokenString, &JWTClaims{},
			s.keyFunc(s.config.SigningMethod, s.config.VerifyingKey))
		if err != nil {
			return err
		}
		claims, ok := token.Claims.(*JWTClaims)
		if !ok || !token.Valid {
			return fmt.Errorf("invalid token")
		}
		// Revoke the session, not the token string, so the refresh token for
		// the same session dies with it.
		if claims.SessionID == "" {
			return fmt.Errorf("session: token carries no session id, so it cannot be revoked")
		}
		return s.revocation.Revoke(ctx, claims.SessionID, claims.ExpiresAt.Time)
	}
	// Without a revocation store there is nowhere to record the logout, and a
	// signed JWT stays valid until it expires. Returning nil here reported a
	// successful logout that had not happened: the caller cleared its cookie,
	// the user believed they were signed out, and anyone holding the token
	// still had a live session. Say so instead.
	return fmt.Errorf("session: logout requires a revocation store; " +
		"configure one with WithRevocationStore, or the token stays valid until it expires")
}

// checkRevoked reports whether the session behind a token has been revoked.
//
// It is a no-op when no revocation store is configured, which keeps stateless
// verification working for deployments that accept it. Delete is the operation
// that refuses to pretend in that configuration.
func (s *JWTStrategy) checkRevoked(ctx context.Context, claims *JWTClaims) error {
	if s.revocation == nil {
		return nil
	}
	if claims.SessionID != "" {
		revoked, err := s.revocation.IsRevoked(ctx, claims.SessionID)
		if err != nil {
			return fmt.Errorf("revocation check failed: %w", err)
		}
		if revoked {
			return fmt.Errorf("session revoked")
		}
	}

	// Identity-level revocation. A token issued at or before the cutoff was
	// live when every session for this identity was ended, so it is revoked
	// even though the store has never seen its session id.
	store, ok := s.revocation.(IdentityRevocationStore)
	if !ok || claims.Subject == "" || claims.IssuedAt == nil {
		return nil
	}
	cutoff, err := store.IdentityRevokedBefore(ctx, claims.Subject)
	if err != nil {
		return fmt.Errorf("identity revocation check failed: %w", err)
	}
	if !cutoff.IsZero() && !claims.IssuedAt.Time.After(cutoff) {
		return fmt.Errorf("session revoked")
	}
	return nil
}

// RevokeAll ends every session belonging to an identity.
//
// JWT sessions are bearer tokens the server never stored, so they cannot be
// enumerated and deleted. Revocation is recorded as a cutoff instead: every
// token issued at or before now stops verifying, while a session created
// afterwards -- the user signing back in -- is unaffected.
//
// This is what makes a password reset mean what users assume it means. Without
// it an attacker holding a stolen session kept it through the victim's reset.
func (s *JWTStrategy) RevokeAll(ctx context.Context, identityID any) error {
	if s.revocation == nil {
		return fmt.Errorf("session: revoking every session requires a revocation store; " +
			"configure one with WithRevocationStore")
	}
	store, ok := s.revocation.(IdentityRevocationStore)
	if !ok {
		return fmt.Errorf("session: the configured revocation store does not implement " +
			"IdentityRevocationStore, so it cannot revoke every session for an identity")
	}
	// RFC 7519 "iat" is a whole number of seconds and jwt.NewNumericDate
	// rounds down to match, so every token minted during the current second
	// carries the same iat regardless of which side of this call it fell on.
	// A timestamp cannot separate them, and the two ways of being wrong are
	// not equal: missing a session leaves an attacker logged in, while
	// catching an extra one costs a user one retry.
	//
	// The cutoff is therefore the start of the current second, and a token is
	// revoked when its iat is at or before it. Every session issued earlier is
	// ended, and so is one issued moments later within the same second. The
	// cutoff must not be pushed into the future: that would revoke sessions
	// created after the call, locking the user out for as long as the skew.
	cutoff := time.Now().Truncate(time.Second)
	return store.RevokeIdentity(ctx, fmt.Sprintf("%v", identityID), cutoff)
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
