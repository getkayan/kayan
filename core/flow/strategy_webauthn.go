package flow

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
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

	// OnCloneWarning is called when a potential credential cloning is detected.
	// This is a security event - log it and consider action.
	OnCloneWarning func(ctx context.Context, ident any, credentialID string)

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
	hooks      WebAuthnHooks

	// sessionStore stores pending registration/login sessions
	// In production, use Redis or database
	sessionStore WebAuthnSessionStore
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
	sessionID := s.generateSessionID()
	sessionData := &WebAuthnSessionData{
		Challenge:        session.Challenge,
		UserID:           session.UserID,
		UserVerification: string(session.UserVerification),
		ExpiresAt:        time.Now().Add(s.sessionTTL),
	}

	if err := s.sessionStore.SaveSession(ctx, sessionID, sessionData); err != nil {
		return nil, "", fmt.Errorf("webauthn: failed to save session: %w", err)
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

	// Retrieve session
	sessionData, err := s.sessionStore.GetSession(ctx, sessionID)
	if err != nil {
		return nil, fmt.Errorf("webauthn: session not found or expired")
	}
	defer s.sessionStore.DeleteSession(ctx, sessionID)

	if time.Now().After(sessionData.ExpiresAt) {
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
		CreatedAt:  time.Now(),
		UpdatedAt:  time.Now(),
	}

	if s.generator != nil {
		cred.ID = fmt.Sprintf("%v", s.generator())
	}

	// If identity supports CredentialSource, add to it
	if cs, ok := ident.(CredentialSource); ok {
		cs.SetCredentials(append(cs.GetCredentials(), *cred))
		if err := s.repo.CreateIdentity(ident); err != nil {
			return nil, fmt.Errorf("webauthn: failed to save credential: %w", err)
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
	// Find identity by identifier
	cred, err := s.repo.GetCredentialByIdentifier(identifier, "")
	if err != nil {
		return nil, "", errors.New("webauthn: user not found")
	}

	ident, err := s.repo.GetIdentity(s.factory, cred.IdentityID)
	if err != nil {
		return nil, "", errors.New("webauthn: user not found")
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
	sessionID := s.generateSessionID()
	sessionData := &WebAuthnSessionData{
		Challenge:        session.Challenge,
		UserID:           session.UserID,
		UserVerification: string(session.UserVerification),
		ExpiresAt:        time.Now().Add(s.sessionTTL),
	}

	// Store allowed credential IDs
	for _, c := range session.AllowedCredentialIDs {
		sessionData.AllowedCredIDs = append(sessionData.AllowedCredIDs, c)
	}

	if err := s.sessionStore.SaveSession(ctx, sessionID, sessionData); err != nil {
		return nil, "", fmt.Errorf("webauthn: failed to save session: %w", err)
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
	// Retrieve session
	sessionData, err := s.sessionStore.GetSession(ctx, sessionID)
	if err != nil {
		return nil, errors.New("webauthn: session not found or expired")
	}
	defer s.sessionStore.DeleteSession(ctx, sessionID)

	if time.Now().After(sessionData.ExpiresAt) {
		return nil, errors.New("webauthn: session expired")
	}

	// Find identity
	cred, err := s.repo.GetCredentialByIdentifier(identifier, "")
	if err != nil {
		return nil, errors.New("webauthn: user not found")
	}

	ident, err := s.repo.GetIdentity(s.factory, cred.IdentityID)
	if err != nil {
		return nil, errors.New("webauthn: user not found")
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

	// Update sign count to prevent replay attacks
	s.updateSignCount(ctx, ident, credential)

	return ident, nil
}

// getExistingCredentials extracts WebAuthn credentials from an identity.
func (s *WebAuthnStrategy) getExistingCredentials(ident any) []webauthn.Credential {
	cs, ok := ident.(CredentialSource)
	if !ok {
		return nil
	}

	var creds []webauthn.Credential
	for _, c := range cs.GetCredentials() {
		if c.Type != "webauthn" {
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

// updateSignCount updates the sign count for a credential after successful auth.
func (s *WebAuthnStrategy) updateSignCount(ctx context.Context, ident any, credential *webauthn.Credential) {
	cs, ok := ident.(CredentialSource)
	if !ok {
		return
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
			creds[i].UpdatedAt = time.Now()
			break
		}
	}

	cs.SetCredentials(creds)
	s.repo.UpdateIdentity(ident)
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
	sessions map[string]*WebAuthnSessionData
}

func NewMemoryWebAuthnSessionStore() *MemoryWebAuthnSessionStore {
	return &MemoryWebAuthnSessionStore{
		sessions: make(map[string]*WebAuthnSessionData),
	}
}

func (s *MemoryWebAuthnSessionStore) SaveSession(ctx context.Context, sessionID string, data *WebAuthnSessionData) error {
	s.sessions[sessionID] = data
	return nil
}

func (s *MemoryWebAuthnSessionStore) GetSession(ctx context.Context, sessionID string) (*WebAuthnSessionData, error) {
	data, ok := s.sessions[sessionID]
	if !ok {
		return nil, errors.New("session not found")
	}
	return data, nil
}

func (s *MemoryWebAuthnSessionStore) DeleteSession(ctx context.Context, sessionID string) error {
	delete(s.sessions, sessionID)
	return nil
}
