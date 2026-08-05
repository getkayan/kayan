package flow

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/getkayan/kayan/core/domain"
	"github.com/getkayan/kayan/core/identity"
	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
)

// WebAuthnUser adapts an identity to the webauthn.User interface.
type WebAuthnUser struct {
	id          []byte
	name        string
	displayName string
	credentials []webauthn.Credential
}

func (u *WebAuthnUser) WebAuthnID() []byte                         { return u.id }
func (u *WebAuthnUser) WebAuthnName() string                       { return u.name }
func (u *WebAuthnUser) WebAuthnDisplayName() string                { return u.displayName }
func (u *WebAuthnUser) WebAuthnCredentials() []webauthn.Credential { return u.credentials }

// WebAuthnCredentialData stores WebAuthn credential details in the Config field.
type WebAuthnCredentialData struct {
	CredentialID    []byte `json:"credential_id"`
	PublicKey       []byte `json:"public_key"`
	AttestationType string `json:"attestation_type"`
	AAGUID          []byte `json:"aaguid"`
	SignCount       uint32 `json:"sign_count"`
	CloneWarning    bool   `json:"clone_warning"`
	BackupEligible  bool   `json:"backup_eligible"`
	BackupState     bool   `json:"backup_state"`
}

// WebAuthnSessionData stores session data during registration/login ceremonies.
type WebAuthnSessionData struct {
	Challenge        string    `json:"challenge"`
	UserID           []byte    `json:"user_id"`
	AllowedCredIDs   [][]byte  `json:"allowed_cred_ids,omitempty"`
	UserVerification string    `json:"user_verification"`
	ExpiresAt        time.Time `json:"expires_at"`
}

// WebAuthnConfig holds configuration for WebAuthn.
type WebAuthnConfig struct {
	RPDisplayName string   // Relying Party display name (e.g., "Kayan Auth")
	RPID          string   // Relying Party ID (e.g., "example.com")
	RPOrigins     []string // Allowed origins (e.g., ["https://example.com"])

	// SessionTTL is how long WebAuthn sessions are valid (default: 5 minutes)
	SessionTTL time.Duration

	// Clock supplies the current time for ceremony expiry. Defaults to
	// domain.SystemClock. Tests drive a ceremony to the exact expiry boundary
	// by supplying a fake.
	Clock domain.Clock

	// Hooks for customizing behavior
	Hooks WebAuthnHooks
}

// WebAuthnHooks provides extension points for customizing WebAuthn behavior.
type WebAuthnHooks struct {
	// BeforeBeginRegistration is called before starting registration.
	// Return error to prevent registration from starting.
	BeforeBeginRegistration func(ctx context.Context, ident any, userName string) error

	// AfterBeginRegistration is called after registration options are created.
	// Can be used for logging or modifying options.
	AfterBeginRegistration func(ctx context.Context, ident any, sessionID string) error

	// BeforeFinishRegistration is called before completing registration.
	BeforeFinishRegistration func(ctx context.Context, ident any, sessionID string) error

	// AfterFinishRegistration is called after credential is created.
	// Receives the new credential for additional processing.
	AfterFinishRegistration func(ctx context.Context, ident any, cred *identity.Credential) error

	// BeforeBeginLogin is called before starting login ceremony.
	BeforeBeginLogin func(ctx context.Context, identifier string) error

	// AfterBeginLogin is called after login options are created.
	AfterBeginLogin func(ctx context.Context, identifier string, sessionID string) error

	// BeforeFinishLogin is called before completing login.
	BeforeFinishLogin func(ctx context.Context, identifier string, sessionID string) error

	// AfterFinishLogin is called after successful login.
	// Receives the authenticated identity.
	AfterFinishLogin func(ctx context.Context, ident any) error

	// OnCloneWarning is called when the authenticator's signature counter went
	// backwards, which means the credential exists in two places: the real
	// authenticator and a copy of it.
	//
	// The login is refused regardless of what this hook does — it is a
	// notification, not a decision point. Use it to alert the user, revoke the
	// credential, or open an incident. To allow the login anyway, set
	// AllowClonedAuthenticators.
	OnCloneWarning func(ctx context.Context, ident any, credentialID string)

	// AllowClonedAuthenticators lets a login proceed after a clone warning.
	//
	// The signature counter exists solely to detect a duplicated authenticator,
	// so ignoring it gives up that detection. Some authenticators — several
	// platform ones, and the Touch ID/Windows Hello style in particular — do
	// not implement a counter at all and always report zero; those never
	// produce a warning, so this option is not needed for them. Set it only if
	// you have a specific authenticator that increments incorrectly and you
	// accept losing clone detection for every credential.
	AllowClonedAuthenticators bool

	// CredentialFilter allows filtering which credentials to use.
	// Return true to include the credential, false to exclude.
	CredentialFilter func(cred *identity.Credential) bool

	// CreateSessionID allows custom session ID generation.
	// If nil, uses default random generation.
	CreateSessionID func() string

	// UserLoader allows custom identity loading for login.
	// If set, bypasses the default identifier-based lookup.
	UserLoader func(ctx context.Context, identifier string) (any, error)

	// CredentialSaver allows custom credential storage.
	// If set, handles credential persistence instead of default behavior.
	CredentialSaver func(ctx context.Context, ident any, cred *identity.Credential) error
}

// WebAuthnStrategy implements WebAuthn/Passkeys authentication.
type WebAuthnStrategy struct {
	repo       IdentityRepository
	webAuthn   *webauthn.WebAuthn
	factory    func() any
	generator  domain.IDGenerator
	sessionTTL time.Duration
	clock      domain.Clock

	// mu guards hooks, which SetHooks may replace after the strategy is
	// already serving ceremonies.
	mu    sync.RWMutex
	hooks WebAuthnHooks

	// sessionStore stores pending registration/login sessions
	// In production, use Redis or database
	sessionStore WebAuthnSessionStore
}

// saveCredential persists a newly registered credential.
//
// This is an update, not an insert: registration attaches a credential to an
// identity that already exists, since BeginRegistration was handed one. It
// previously called CreateIdentity, which fails on any storage that treats a
// create as an insert — enrolling a second passkey returned a duplicate-key
// error after the ceremony had already succeeded, so the credential was lost.
//
// CredentialSaver takes over persistence entirely when supplied.
func (s *WebAuthnStrategy) saveCredential(ctx context.Context, ident any, cred *identity.Credential, hooks WebAuthnHooks) error {
	if hooks.CredentialSaver != nil {
		if err := hooks.CredentialSaver(ctx, ident, cred); err != nil {
			return fmt.Errorf("webauthn: failed to save credential: %w", err)
		}
		return nil
	}

	cs, ok := ident.(CredentialSource)
	if !ok {
		return nil
	}

	cs.SetCredentials(append(cs.GetCredentials(), *cred))
	if err := s.repo.UpdateIdentity(ctx, ident); err != nil {
		return fmt.Errorf("webauthn: failed to save credential: %w", err)
	}
	return nil
}

// loadUser resolves the identity for an identifier, deferring to the
// UserLoader hook when one is set.
//
// The default path looks up the credential and then the identity it belongs
// to, which assumes the caller stores WebAuthn credentials the way Kayan does.
// UserLoader is the seam for anyone who does not.
func (s *WebAuthnStrategy) loadUser(ctx context.Context, identifier string, hooks WebAuthnHooks) (any, error) {
	if hooks.UserLoader != nil {
		ident, err := hooks.UserLoader(ctx, identifier)
		if err != nil {
			return nil, err
		}
		if ident == nil {
			return nil, errors.New("webauthn: user not found")
		}
		return ident, nil
	}

	cred, err := s.repo.GetCredentialByIdentifier(ctx, identifier, "")
	if err != nil {
		return nil, errors.New("webauthn: user not found")
	}

	ident, err := s.repo.GetIdentity(ctx, s.factory, cred.IdentityID)
	if err != nil {
		return nil, errors.New("webauthn: user not found")
	}
	return ident, nil
}

// newSessionID returns a ceremony session ID, deferring to the CreateSessionID
// hook when one is set.
func (s *WebAuthnStrategy) newSessionID(hooks WebAuthnHooks) string {
	if hooks.CreateSessionID != nil {
		return hooks.CreateSessionID()
	}
	return s.generateSessionID()
}

// getHooks returns a snapshot of the configured hooks.
func (s *WebAuthnStrategy) getHooks() WebAuthnHooks {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.hooks
}

// WebAuthnSessionStore interface for storing WebAuthn ceremony sessions.
type WebAuthnSessionStore interface {
	SaveSession(ctx context.Context, sessionID string, data *WebAuthnSessionData) error
	GetSession(ctx context.Context, sessionID string) (*WebAuthnSessionData, error)
	DeleteSession(ctx context.Context, sessionID string) error
}

// NewWebAuthnStrategy creates a new WebAuthn strategy.
func NewWebAuthnStrategy(
	repo IdentityRepository,
	config WebAuthnConfig,
	factory func() any,
	sessionStore WebAuthnSessionStore,
) (*WebAuthnStrategy, error) {
	wconfig := &webauthn.Config{
		RPDisplayName: config.RPDisplayName,
		RPID:          config.RPID,
		RPOrigins:     config.RPOrigins,
	}

	wa, err := webauthn.New(wconfig)
	if err != nil {
		return nil, fmt.Errorf("webauthn: failed to create instance: %w", err)
	}

	sessionTTL := config.SessionTTL
	if sessionTTL == 0 {
		sessionTTL = 5 * time.Minute
	}

	return &WebAuthnStrategy{
		repo:         repo,
		webAuthn:     wa,
		factory:      factory,
		sessionStore: sessionStore,
		sessionTTL:   sessionTTL,
		clock:        domain.ClockOrDefault(config.Clock),
		hooks:        config.Hooks,
	}, nil
}

func (s *WebAuthnStrategy) ID() string { return "webauthn" }

// SetIDGenerator sets the ID generator for new credentials.
func (s *WebAuthnStrategy) SetIDGenerator(g domain.IDGenerator) {
	s.generator = g
}

// SetHooks allows updating hooks after creation.
func (s *WebAuthnStrategy) SetHooks(hooks WebAuthnHooks) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.hooks = hooks
}

// SetSessionTTL allows updating the session TTL after creation.
func (s *WebAuthnStrategy) SetSessionTTL(ttl time.Duration) {
	s.sessionTTL = ttl
}

// BeginRegistration starts the WebAuthn registration ceremony.
// Returns the options to send to the client and a session ID for verification.
func (s *WebAuthnStrategy) BeginRegistration(
	ctx context.Context,
	ident any,
	userName, displayName string,
) (*protocol.CredentialCreation, string, error) {
	fi, ok := ident.(FlowIdentity)
	if !ok {
		return nil, "", errors.New("webauthn: identity must implement FlowIdentity")
	}

	hooks := s.getHooks()
	if hooks.BeforeBeginRegistration != nil {
		if err := hooks.BeforeBeginRegistration(ctx, ident, userName); err != nil {
			return nil, "", err
		}
	}

	userID := []byte(fmt.Sprintf("%v", fi.GetID()))

	// Get existing credentials for this user
	existingCreds := s.getExistingCredentials(ident)

	user := &WebAuthnUser{
		id:          userID,
		name:        userName,
		displayName: displayName,
		credentials: existingCreds,
	}

	options, session, err := s.webAuthn.BeginRegistration(user)
	if err != nil {
		return nil, "", fmt.Errorf("webauthn: begin registration failed: %w", err)
	}

	// Store session
	sessionID := s.newSessionID(hooks)
	sessionData := &WebAuthnSessionData{
		Challenge:        session.Challenge,
		UserID:           session.UserID,
		UserVerification: string(session.UserVerification),
		ExpiresAt:        s.clock.Now().Add(s.sessionTTL),
	}

	if err := s.sessionStore.SaveSession(ctx, sessionID, sessionData); err != nil {
		return nil, "", fmt.Errorf("webauthn: failed to save session: %w", err)
	}

	if hooks.AfterBeginRegistration != nil {
		if err := hooks.AfterBeginRegistration(ctx, ident, sessionID); err != nil {
			return nil, "", err
		}
	}

	return options, sessionID, nil
}

// FinishRegistration completes the WebAuthn registration ceremony.
// Returns the created credential.
func (s *WebAuthnStrategy) FinishRegistration(
	ctx context.Context,
	ident any,
	sessionID string,
	userName, displayName string,
	response *protocol.ParsedCredentialCreationData,
) (*identity.Credential, error) {
	fi, ok := ident.(FlowIdentity)
	if !ok {
		return nil, errors.New("webauthn: identity must implement FlowIdentity")
	}

	hooks := s.getHooks()
	if hooks.BeforeFinishRegistration != nil {
		if err := hooks.BeforeFinishRegistration(ctx, ident, sessionID); err != nil {
			return nil, err
		}
	}

	// Retrieve session
	sessionData, err := s.sessionStore.GetSession(ctx, sessionID)
	if err != nil {
		return nil, fmt.Errorf("webauthn: session not found or expired")
	}
	defer s.sessionStore.DeleteSession(ctx, sessionID)

	if s.clock.Now().After(sessionData.ExpiresAt) {
		return nil, errors.New("webauthn: session expired")
	}

	userID := []byte(fmt.Sprintf("%v", fi.GetID()))
	existingCreds := s.getExistingCredentials(ident)

	user := &WebAuthnUser{
		id:          userID,
		name:        userName,
		displayName: displayName,
		credentials: existingCreds,
	}

	waSession := webauthn.SessionData{
		Challenge:        sessionData.Challenge,
		UserID:           sessionData.UserID,
		UserVerification: protocol.UserVerificationRequirement(sessionData.UserVerification),
	}

	credential, err := s.webAuthn.CreateCredential(user, waSession, response)
	if err != nil {
		return nil, fmt.Errorf("webauthn: credential creation failed: %w", err)
	}

	// Store credential
	credData := WebAuthnCredentialData{
		CredentialID:    credential.ID,
		PublicKey:       credential.PublicKey,
		AttestationType: credential.AttestationType,
		AAGUID:          credential.Authenticator.AAGUID,
		SignCount:       credential.Authenticator.SignCount,
		CloneWarning:    credential.Authenticator.CloneWarning,
		BackupEligible:  credential.Flags.BackupEligible,
		BackupState:     credential.Flags.BackupState,
	}

	configBytes, err := json.Marshal(credData)
	if err != nil {
		return nil, fmt.Errorf("webauthn: failed to marshal credential config: %w", err)
	}

	cred := &identity.Credential{
		IdentityID: fmt.Sprintf("%v", fi.GetID()),
		Type:       "webauthn",
		Identifier: base64.RawURLEncoding.EncodeToString(credential.ID),
		Config:     identity.JSON(configBytes),
		CreatedAt:  s.clock.Now(),
		UpdatedAt:  s.clock.Now(),
	}

	if s.generator != nil {
		cred.ID = fmt.Sprintf("%v", s.generator())
	}

	if err := s.saveCredential(ctx, ident, cred, hooks); err != nil {
		return nil, err
	}

	if hooks.AfterFinishRegistration != nil {
		if err := hooks.AfterFinishRegistration(ctx, ident, cred); err != nil {
			return nil, err
		}
	}

	return cred, nil
}

// BeginLogin starts the WebAuthn login ceremony.
// Returns the options to send to the client and a session ID for verification.
func (s *WebAuthnStrategy) BeginLogin(
	ctx context.Context,
	identifier string,
) (*protocol.CredentialAssertion, string, error) {
	hooks := s.getHooks()
	if hooks.BeforeBeginLogin != nil {
		if err := hooks.BeforeBeginLogin(ctx, identifier); err != nil {
			return nil, "", err
		}
	}

	ident, err := s.loadUser(ctx, identifier, hooks)
	if err != nil {
		return nil, "", err
	}

	fi, ok := ident.(FlowIdentity)
	if !ok {
		return nil, "", errors.New("webauthn: identity must implement FlowIdentity")
	}

	userID := []byte(fmt.Sprintf("%v", fi.GetID()))
	existingCreds := s.getExistingCredentials(ident)

	if len(existingCreds) == 0 {
		return nil, "", errors.New("webauthn: no credentials registered")
	}

	user := &WebAuthnUser{
		id:          userID,
		name:        identifier,
		displayName: identifier,
		credentials: existingCreds,
	}

	options, session, err := s.webAuthn.BeginLogin(user)
	if err != nil {
		return nil, "", fmt.Errorf("webauthn: begin login failed: %w", err)
	}

	// Store session
	sessionID := s.newSessionID(hooks)
	sessionData := &WebAuthnSessionData{
		Challenge:        session.Challenge,
		UserID:           session.UserID,
		UserVerification: string(session.UserVerification),
		ExpiresAt:        s.clock.Now().Add(s.sessionTTL),
	}

	// Store allowed credential IDs
	for _, c := range session.AllowedCredentialIDs {
		sessionData.AllowedCredIDs = append(sessionData.AllowedCredIDs, c)
	}

	if err := s.sessionStore.SaveSession(ctx, sessionID, sessionData); err != nil {
		return nil, "", fmt.Errorf("webauthn: failed to save session: %w", err)
	}

	if hooks.AfterBeginLogin != nil {
		if err := hooks.AfterBeginLogin(ctx, identifier, sessionID); err != nil {
			return nil, "", err
		}
	}

	return options, sessionID, nil
}

// Authenticate completes the WebAuthn login ceremony.
// Implements LoginStrategy interface.
// identifier = email/username, secret = JSON-encoded assertion response + sessionID
func (s *WebAuthnStrategy) Authenticate(ctx context.Context, identifier, secret string) (any, error) {
	// Parse the secret which contains sessionID and assertion response
	var authData struct {
		SessionID string                                  `json:"session_id"`
		Response  *protocol.ParsedCredentialAssertionData `json:"response"`
	}

	if err := json.Unmarshal([]byte(secret), &authData); err != nil {
		return nil, errors.New("webauthn: invalid authentication data")
	}

	return s.FinishLogin(ctx, identifier, authData.SessionID, authData.Response)
}

// FinishLogin completes the WebAuthn login ceremony.
func (s *WebAuthnStrategy) FinishLogin(
	ctx context.Context,
	identifier string,
	sessionID string,
	response *protocol.ParsedCredentialAssertionData,
) (any, error) {
	hooks := s.getHooks()
	if hooks.BeforeFinishLogin != nil {
		if err := hooks.BeforeFinishLogin(ctx, identifier, sessionID); err != nil {
			return nil, err
		}
	}

	// Retrieve session
	sessionData, err := s.sessionStore.GetSession(ctx, sessionID)
	if err != nil {
		return nil, errors.New("webauthn: session not found or expired")
	}
	defer s.sessionStore.DeleteSession(ctx, sessionID)

	if s.clock.Now().After(sessionData.ExpiresAt) {
		return nil, errors.New("webauthn: session expired")
	}

	ident, err := s.loadUser(ctx, identifier, hooks)
	if err != nil {
		return nil, err
	}

	fi, ok := ident.(FlowIdentity)
	if !ok {
		return nil, errors.New("webauthn: identity must implement FlowIdentity")
	}

	userID := []byte(fmt.Sprintf("%v", fi.GetID()))
	existingCreds := s.getExistingCredentials(ident)

	user := &WebAuthnUser{
		id:          userID,
		name:        identifier,
		displayName: identifier,
		credentials: existingCreds,
	}

	waSession := webauthn.SessionData{
		Challenge:            sessionData.Challenge,
		UserID:               sessionData.UserID,
		AllowedCredentialIDs: sessionData.AllowedCredIDs,
		UserVerification:     protocol.UserVerificationRequirement(sessionData.UserVerification),
	}

	credential, err := s.webAuthn.ValidateLogin(user, waSession, response)
	if err != nil {
		return nil, fmt.Errorf("webauthn: login validation failed: %w", err)
	}

	// Update sign count to prevent replay attacks. This runs before the clone
	// check below so the warning is persisted even though the login is about
	// to be refused — otherwise the evidence is lost and the next attempt
	// starts from a clean counter.
	if err := s.updateSignCount(ctx, ident, credential); err != nil {
		return nil, fmt.Errorf("webauthn: failed to persist sign count: %w", err)
	}

	// A backwards signature counter means the credential exists in two places.
	// Recording that and letting the login through would be recording a
	// break-in and opening the door.
	if credential.Authenticator.CloneWarning {
		credID := base64.RawURLEncoding.EncodeToString(credential.ID)
		if hooks.OnCloneWarning != nil {
			hooks.OnCloneWarning(ctx, ident, credID)
		}
		if !hooks.AllowClonedAuthenticators {
			return nil, fmt.Errorf("%w: credential %s", ErrWebAuthnClonedCredential, credID)
		}
	}

	if hooks.AfterFinishLogin != nil {
		if err := hooks.AfterFinishLogin(ctx, ident); err != nil {
			return nil, err
		}
	}

	return ident, nil
}

// getExistingCredentials extracts WebAuthn credentials from an identity.
func (s *WebAuthnStrategy) getExistingCredentials(ident any) []webauthn.Credential {
	cs, ok := ident.(CredentialSource)
	if !ok {
		return nil
	}

	filter := s.getHooks().CredentialFilter

	var creds []webauthn.Credential
	for _, c := range cs.GetCredentials() {
		if c.Type != "webauthn" {
			continue
		}

		if filter != nil && !filter(&c) {
			continue
		}

		var data WebAuthnCredentialData
		if err := json.Unmarshal(c.Config, &data); err != nil {
			continue
		}

		creds = append(creds, webauthn.Credential{
			ID:              data.CredentialID,
			PublicKey:       data.PublicKey,
			AttestationType: data.AttestationType,
			Authenticator: webauthn.Authenticator{
				AAGUID:       data.AAGUID,
				SignCount:    data.SignCount,
				CloneWarning: data.CloneWarning,
			},
			Flags: webauthn.CredentialFlags{
				BackupEligible: data.BackupEligible,
				BackupState:    data.BackupState,
			},
		})
	}

	return creds
}

// updateSignCount persists the authenticator counter after a successful
// assertion.
//
// The error is returned rather than dropped. A failed write means the stored
// counter stops advancing, and a counter that never advances can never go
// backwards — so a silent failure here disables clone detection for that
// credential permanently, which is exactly the case a caller needs to know
// about.
func (s *WebAuthnStrategy) updateSignCount(ctx context.Context, ident any, credential *webauthn.Credential) error {
	cs, ok := ident.(CredentialSource)
	if !ok {
		return nil
	}

	credID := base64.RawURLEncoding.EncodeToString(credential.ID)
	creds := cs.GetCredentials()

	for i, c := range creds {
		if c.Type == "webauthn" && c.Identifier == credID {
			var data WebAuthnCredentialData
			if err := json.Unmarshal(c.Config, &data); err != nil {
				continue
			}

			data.SignCount = credential.Authenticator.SignCount
			data.CloneWarning = credential.Authenticator.CloneWarning

			configBytes, err := json.Marshal(data)
			if err != nil {
				continue
			}

			creds[i].Config = identity.JSON(configBytes)
			creds[i].UpdatedAt = s.clock.Now()
			break
		}
	}

	cs.SetCredentials(creds)
	return s.repo.UpdateIdentity(ctx, ident)
}

func (s *WebAuthnStrategy) generateSessionID() string {
	b := make([]byte, 32)
	rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

// ---- Memory Session Store (for development/testing) ----

// MemoryWebAuthnSessionStore is an in-memory implementation of WebAuthnSessionStore.
// Use Redis in production.
type MemoryWebAuthnSessionStore struct {
	mu       sync.RWMutex
	sessions map[string]*WebAuthnSessionData
}

func NewMemoryWebAuthnSessionStore() *MemoryWebAuthnSessionStore {
	return &MemoryWebAuthnSessionStore{
		sessions: make(map[string]*WebAuthnSessionData),
	}
}

func (s *MemoryWebAuthnSessionStore) SaveSession(ctx context.Context, sessionID string, data *WebAuthnSessionData) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sessions[sessionID] = data
	return nil
}

func (s *MemoryWebAuthnSessionStore) GetSession(ctx context.Context, sessionID string) (*WebAuthnSessionData, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	data, ok := s.sessions[sessionID]
	if !ok {
		return nil, errors.New("session not found")
	}
	return data, nil
}

func (s *MemoryWebAuthnSessionStore) DeleteSession(ctx context.Context, sessionID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.sessions, sessionID)
	return nil
}
