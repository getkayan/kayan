package session

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/getkayan/kayan/core/domain"
	"github.com/google/uuid"
)

var (
	ErrSSONotFound    = errors.New("sso: session not found")
	ErrSSOInactive    = errors.New("sso: session is not active")
	ErrSSOExpired     = errors.New("sso: session expired")
	ErrSSOAppNotFound = errors.New("sso: app not found")
)

// SSOSession represents a single sign-on session spanning applications.
type SSOSession struct {
	ID          string       `json:"id"`
	IdentityID  string       `json:"identity_id"`
	AppSessions []AppSession `json:"app_sessions"`
	CreatedAt   time.Time    `json:"created_at"`
	ExpiresAt   time.Time    `json:"expires_at"`
	Active      bool         `json:"active"`
}

// AppSession represents one application's membership in an SSO session.
type AppSession struct {
	AppID     string    `json:"app_id"`
	SessionID string    `json:"session_id"`
	CreatedAt time.Time `json:"created_at"`
}

// SSOStore persists SSO sessions. Mutation methods must be atomic so separate
// application processes cannot overwrite each other's memberships.
type SSOStore interface {
	CreateOrJoinSSOSession(ctx context.Context, candidate *SSOSession) (*SSOSession, error)
	GetSSOSession(ctx context.Context, id string) (*SSOSession, error)
	GetSSOSessionByIdentity(ctx context.Context, identityID string) (*SSOSession, error)
	JoinSSOSession(ctx context.Context, id string, app AppSession) (*AppSession, error)
	LeaveSSOSession(ctx context.Context, id, appID string) error
	DeactivateSSOSession(ctx context.Context, id string) ([]AppSession, error)
	DeleteSSOSession(ctx context.Context, id string) error
}

// SSOManager orchestrates cross-application sessions without choosing storage.
type SSOManager struct {
	store       SSOStore
	ttl         time.Duration
	clock       domain.Clock
	idGenerator domain.IDGenerator
}

// SSOManagerOption configures an SSOManager.
type SSOManagerOption func(*SSOManager)

// WithSSOTTL sets the session TTL. The default is eight hours.
func WithSSOTTL(ttl time.Duration) SSOManagerOption { return func(m *SSOManager) { m.ttl = ttl } }

// WithSSOClock sets the clock used for timestamps and expiry checks.
func WithSSOClock(clock domain.Clock) SSOManagerOption {
	return func(m *SSOManager) { m.clock = clock }
}

// WithSSOIDGenerator sets the generator used for SSO and app-session IDs.
func WithSSOIDGenerator(generator domain.IDGenerator) SSOManagerOption {
	return func(m *SSOManager) { m.idGenerator = generator }
}

// NewSSOManager creates an SSO manager around the caller's store.
func NewSSOManager(store SSOStore, opts ...SSOManagerOption) *SSOManager {
	m := &SSOManager{store: store, ttl: 8 * time.Hour, clock: domain.SystemClock, idGenerator: func() any { return uuid.NewString() }}
	for _, opt := range opts {
		opt(m)
	}
	m.clock = domain.ClockOrDefault(m.clock)
	if m.idGenerator == nil {
		m.idGenerator = func() any { return uuid.NewString() }
	}
	return m
}

// CreateSession creates a session or atomically joins the identity's active one.
func (m *SSOManager) CreateSession(ctx context.Context, identityID, appID string) (*SSOSession, error) {
	if identityID == "" {
		return nil, errors.New("sso: identity ID is required")
	}
	if appID == "" {
		return nil, errors.New("sso: app ID is required")
	}
	now := m.clock.Now()
	candidate := &SSOSession{
		ID: fmt.Sprint(m.idGenerator()), IdentityID: identityID,
		AppSessions: []AppSession{{AppID: appID, SessionID: fmt.Sprint(m.idGenerator()), CreatedAt: now}},
		CreatedAt:   now, ExpiresAt: now.Add(m.ttl), Active: true,
	}
	session, err := m.store.CreateOrJoinSSOSession(ctx, candidate)
	if err != nil {
		return nil, fmt.Errorf("sso: create session: %w", err)
	}
	return session, nil
}

// JoinSession atomically adds an application to an active SSO session.
func (m *SSOManager) JoinSession(ctx context.Context, id, appID string) (*AppSession, error) {
	if appID == "" {
		return nil, errors.New("sso: app ID is required")
	}
	app, err := m.store.JoinSSOSession(ctx, id, AppSession{AppID: appID, SessionID: fmt.Sprint(m.idGenerator()), CreatedAt: m.clock.Now()})
	if err != nil {
		return nil, fmt.Errorf("sso: join session: %w", err)
	}
	return app, nil
}

// Logout atomically deactivates an SSO session and returns its app sessions.
func (m *SSOManager) Logout(ctx context.Context, id string) ([]AppSession, error) {
	apps, err := m.store.DeactivateSSOSession(ctx, id)
	if err != nil {
		return nil, fmt.Errorf("sso: deactivate session: %w", err)
	}
	return apps, nil
}

// LogoutApp removes one application, deactivating the SSO session if empty.
func (m *SSOManager) LogoutApp(ctx context.Context, id, appID string) error {
	if err := m.store.LeaveSSOSession(ctx, id, appID); err != nil {
		return fmt.Errorf("sso: leave session: %w", err)
	}
	return nil
}

// GetSession retrieves an SSO session by ID.
func (m *SSOManager) GetSession(ctx context.Context, id string) (*SSOSession, error) {
	return m.store.GetSSOSession(ctx, id)
}

// GetSessionByIdentity retrieves an identity's active SSO session.
func (m *SSOManager) GetSessionByIdentity(ctx context.Context, identityID string) (*SSOSession, error) {
	return m.store.GetSSOSessionByIdentity(ctx, identityID)
}

// MemorySSOStore is a concurrency-safe in-memory SSOStore for tests and development.
type MemorySSOStore struct {
	mu       sync.RWMutex
	sessions map[string]*SSOSession
}

// NewMemorySSOStore creates an empty in-memory store.
func NewMemorySSOStore() *MemorySSOStore {
	return &MemorySSOStore{sessions: make(map[string]*SSOSession)}
}

func (s *MemorySSOStore) CreateOrJoinSSOSession(_ context.Context, candidate *SSOSession) (*SSOSession, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, existing := range s.sessions {
		if existing.IdentityID != candidate.IdentityID || !existing.Active || !existing.ExpiresAt.After(candidate.CreatedAt) {
			continue
		}
		app := candidate.AppSessions[0]
		for _, current := range existing.AppSessions {
			if current.AppID == app.AppID {
				return cloneSSOSession(existing), nil
			}
		}
		existing.AppSessions = append(existing.AppSessions, app)
		return cloneSSOSession(existing), nil
	}
	s.sessions[candidate.ID] = cloneSSOSession(candidate)
	return cloneSSOSession(candidate), nil
}

func (s *MemorySSOStore) GetSSOSession(_ context.Context, id string) (*SSOSession, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	session, ok := s.sessions[id]
	if !ok {
		return nil, fmt.Errorf("%w: %s", ErrSSONotFound, id)
	}
	return cloneSSOSession(session), nil
}

func (s *MemorySSOStore) GetSSOSessionByIdentity(_ context.Context, identityID string) (*SSOSession, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, session := range s.sessions {
		if session.IdentityID == identityID && session.Active {
			return cloneSSOSession(session), nil
		}
	}
	return nil, fmt.Errorf("%w: identity %s", ErrSSONotFound, identityID)
}

func (s *MemorySSOStore) JoinSSOSession(_ context.Context, id string, app AppSession) (*AppSession, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	session, ok := s.sessions[id]
	if !ok {
		return nil, ErrSSONotFound
	}
	if !session.Active {
		return nil, ErrSSOInactive
	}
	if !app.CreatedAt.Before(session.ExpiresAt) {
		return nil, ErrSSOExpired
	}
	for _, current := range session.AppSessions {
		if current.AppID == app.AppID {
			copy := current
			return &copy, nil
		}
	}
	session.AppSessions = append(session.AppSessions, app)
	copy := app
	return &copy, nil
}

func (s *MemorySSOStore) LeaveSSOSession(_ context.Context, id, appID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	session, ok := s.sessions[id]
	if !ok {
		return ErrSSONotFound
	}
	apps := make([]AppSession, 0, len(session.AppSessions))
	found := false
	for _, app := range session.AppSessions {
		if app.AppID == appID {
			found = true
			continue
		}
		apps = append(apps, app)
	}
	if !found {
		return fmt.Errorf("%w: %s", ErrSSOAppNotFound, appID)
	}
	session.AppSessions = apps
	if len(apps) == 0 {
		session.Active = false
	}
	return nil
}

func (s *MemorySSOStore) DeactivateSSOSession(_ context.Context, id string) ([]AppSession, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	session, ok := s.sessions[id]
	if !ok {
		return nil, ErrSSONotFound
	}
	session.Active = false
	return append([]AppSession(nil), session.AppSessions...), nil
}

func (s *MemorySSOStore) DeleteSSOSession(_ context.Context, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.sessions, id)
	return nil
}

func cloneSSOSession(session *SSOSession) *SSOSession {
	clone := *session
	clone.AppSessions = append([]AppSession(nil), session.AppSessions...)
	return &clone
}
