package session

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/google/uuid"
)

// SSOSession represents a single sign-on session spanning multiple applications.
// When a user authenticates once, child AppSessions are created for each application
// they access. Global logout revokes all child sessions.
type SSOSession struct {
	ID          string       `json:"id"`
	IdentityID  string       `json:"identity_id"`
	AppSessions []AppSession `json:"app_sessions"`
	CreatedAt   time.Time    `json:"created_at"`
	ExpiresAt   time.Time    `json:"expires_at"`
	Active      bool         `json:"active"`
}

// AppSession represents a child session within an SSO session for a specific application.
type AppSession struct {
	AppID     string    `json:"app_id"`
	SessionID string    `json:"session_id"`
	CreatedAt time.Time `json:"created_at"`
}

// SSOStore persists SSO sessions.
type SSOStore interface {
	// CreateSSOSession persists a new SSO session.
	CreateSSOSession(ctx context.Context, session *SSOSession) error

	// GetSSOSession retrieves an SSO session by its ID.
	GetSSOSession(ctx context.Context, id string) (*SSOSession, error)

	// GetSSOSessionByIdentity retrieves the active SSO session for an identity.
	GetSSOSessionByIdentity(ctx context.Context, identityID string) (*SSOSession, error)

	// UpdateSSOSession updates an existing SSO session (e.g., adding app sessions).
	UpdateSSOSession(ctx context.Context, session *SSOSession) error

	// DeleteSSOSession removes an SSO session.
	DeleteSSOSession(ctx context.Context, id string) error
}

// SSOManager orchestrates cross-application single sign-on sessions.
//
// Usage:
//
//	store := session.NewMemorySSOStore()
//	mgr := session.NewSSOManager(store)
//
//	// User logs into first app
//	ssoSession, _ := mgr.CreateSession(ctx, "user-123", "app-web")
//
//	// User accesses second app, joins existing SSO session
//	appSession, _ := mgr.JoinSession(ctx, ssoSession.ID, "app-mobile")
//
//	// Global logout: revokes all app sessions
//	apps, _ := mgr.Logout(ctx, ssoSession.ID)
//	// Caller is responsible for invalidating each app's session
//	for _, app := range apps {
//	    appSessionManager.Delete(app.SessionID)
//	}
type SSOManager struct {
	store    SSOStore
	ttl      time.Duration
}

// SSOManagerOption configures an SSOManager.
type SSOManagerOption func(*SSOManager)

// WithSSOTTL sets the default TTL for SSO sessions. Default is 8 hours.
func WithSSOTTL(ttl time.Duration) SSOManagerOption {
	return func(m *SSOManager) { m.ttl = ttl }
}

// NewSSOManager creates a new SSO session manager.
func NewSSOManager(store SSOStore, opts ...SSOManagerOption) *SSOManager {
	m := &SSOManager{
		store: store,
		ttl:   8 * time.Hour,
	}
	for _, opt := range opts {
		opt(m)
	}
	return m
}

// CreateSession creates a new SSO session and registers the first application.
// Returns the SSO session with the initial AppSession.
func (m *SSOManager) CreateSession(ctx context.Context, identityID, appID string) (*SSOSession, error) {
	if identityID == "" {
		return nil, fmt.Errorf("sso: identity ID is required")
	}
	if appID == "" {
		return nil, fmt.Errorf("sso: app ID is required")
	}

	// Check for existing active SSO session
	existing, err := m.store.GetSSOSessionByIdentity(ctx, identityID)
	if err == nil && existing != nil && existing.Active && existing.ExpiresAt.After(time.Now()) {
		// Join existing session instead
		return m.joinExisting(ctx, existing, appID)
	}

	now := time.Now()
	session := &SSOSession{
		ID:         uuid.New().String(),
		IdentityID: identityID,
		AppSessions: []AppSession{
			{
				AppID:     appID,
				SessionID: uuid.New().String(),
				CreatedAt: now,
			},
		},
		CreatedAt: now,
		ExpiresAt: now.Add(m.ttl),
		Active:    true,
	}

	if err := m.store.CreateSSOSession(ctx, session); err != nil {
		return nil, fmt.Errorf("sso: failed to create session: %w", err)
	}

	return session, nil
}

// JoinSession adds an application to an existing SSO session.
// Returns the newly created AppSession for the joining app.
func (m *SSOManager) JoinSession(ctx context.Context, ssoSessionID, appID string) (*AppSession, error) {
	session, err := m.store.GetSSOSession(ctx, ssoSessionID)
	if err != nil {
		return nil, fmt.Errorf("sso: session not found: %w", err)
	}

	if !session.Active {
		return nil, fmt.Errorf("sso: session is not active")
	}

	if session.ExpiresAt.Before(time.Now()) {
		return nil, fmt.Errorf("sso: session expired")
	}

	// Check if app already joined
	for _, app := range session.AppSessions {
		if app.AppID == appID {
			return &app, nil
		}
	}

	joined, err := m.joinExisting(ctx, session, appID)
	if err != nil {
		return nil, err
	}

	// Return the last added app session
	return &joined.AppSessions[len(joined.AppSessions)-1], nil
}

// joinExisting adds an app to an existing session.
func (m *SSOManager) joinExisting(ctx context.Context, session *SSOSession, appID string) (*SSOSession, error) {
	// Check if already joined
	for _, app := range session.AppSessions {
		if app.AppID == appID {
			return session, nil
		}
	}

	appSession := AppSession{
		AppID:     appID,
		SessionID: uuid.New().String(),
		CreatedAt: time.Now(),
	}
	session.AppSessions = append(session.AppSessions, appSession)

	if err := m.store.UpdateSSOSession(ctx, session); err != nil {
		return nil, fmt.Errorf("sso: failed to add app session: %w", err)
	}

	return session, nil
}

// Logout performs a global logout by deactivating the SSO session.
// Returns all AppSessions so the caller can invalidate each one.
// Kayan is headless — it does not know how to tear down individual app sessions.
func (m *SSOManager) Logout(ctx context.Context, ssoSessionID string) ([]AppSession, error) {
	session, err := m.store.GetSSOSession(ctx, ssoSessionID)
	if err != nil {
		return nil, fmt.Errorf("sso: session not found: %w", err)
	}

	apps := make([]AppSession, len(session.AppSessions))
	copy(apps, session.AppSessions)

	session.Active = false
	if err := m.store.UpdateSSOSession(ctx, session); err != nil {
		return nil, fmt.Errorf("sso: failed to deactivate session: %w", err)
	}

	return apps, nil
}

// LogoutApp removes a single application from the SSO session.
// The SSO session remains active for other applications.
func (m *SSOManager) LogoutApp(ctx context.Context, ssoSessionID, appID string) error {
	session, err := m.store.GetSSOSession(ctx, ssoSessionID)
	if err != nil {
		return fmt.Errorf("sso: session not found: %w", err)
	}

	filtered := make([]AppSession, 0, len(session.AppSessions))
	found := false
	for _, app := range session.AppSessions {
		if app.AppID == appID {
			found = true
			continue
		}
		filtered = append(filtered, app)
	}

	if !found {
		return fmt.Errorf("sso: app %q not found in session", appID)
	}

	session.AppSessions = filtered

	// If no apps remain, deactivate the SSO session
	if len(session.AppSessions) == 0 {
		session.Active = false
	}

	return m.store.UpdateSSOSession(ctx, session)
}

// GetSession retrieves an SSO session by ID.
func (m *SSOManager) GetSession(ctx context.Context, ssoSessionID string) (*SSOSession, error) {
	return m.store.GetSSOSession(ctx, ssoSessionID)
}

// GetSessionByIdentity retrieves the active SSO session for an identity.
func (m *SSOManager) GetSessionByIdentity(ctx context.Context, identityID string) (*SSOSession, error) {
	return m.store.GetSSOSessionByIdentity(ctx, identityID)
}

// --- In-Memory SSOStore ---

// MemorySSOStore is an in-memory implementation of SSOStore for testing.
type MemorySSOStore struct {
	mu       sync.RWMutex
	sessions map[string]*SSOSession
}

// NewMemorySSOStore creates a new in-memory SSO store.
func NewMemorySSOStore() *MemorySSOStore {
	return &MemorySSOStore{
		sessions: make(map[string]*SSOSession),
	}
}

func (s *MemorySSOStore) CreateSSOSession(ctx context.Context, session *SSOSession) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sessions[session.ID] = session
	return nil
}

func (s *MemorySSOStore) GetSSOSession(ctx context.Context, id string) (*SSOSession, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	sess, ok := s.sessions[id]
	if !ok {
		return nil, fmt.Errorf("sso: session not found: %s", id)
	}
	return sess, nil
}

func (s *MemorySSOStore) GetSSOSessionByIdentity(ctx context.Context, identityID string) (*SSOSession, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, sess := range s.sessions {
		if sess.IdentityID == identityID && sess.Active {
			return sess, nil
		}
	}
	return nil, fmt.Errorf("sso: no active session for identity: %s", identityID)
}

func (s *MemorySSOStore) UpdateSSOSession(ctx context.Context, session *SSOSession) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sessions[session.ID] = session
	return nil
}

func (s *MemorySSOStore) DeleteSSOSession(ctx context.Context, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.sessions, id)
	return nil
}
