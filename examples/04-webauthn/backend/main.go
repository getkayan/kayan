// 04-webauthn: WebAuthn / Passkey authentication backed by Kayan.
//
// Demonstrates:
//   - flow.NewWebAuthnStrategy() with real cryptographic verification
//   - Four-step ceremony: register/begin, register/finish, login/begin, login/finish
//   - In-memory WebAuthnSessionStore and IdentityStorage
//   - JWT session via session.NewHS256Strategy()
//
// NOTE: This requires a WebAuthn-capable browser. The RPID must match your origin.
// For local development set RPID=localhost and ORIGIN=http://localhost:5173.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"reflect"
	"strings"
	"sync"
	"time"

	"github.com/getkayan/kayan/core/flow"
	"github.com/getkayan/kayan/core/identity"
	"github.com/getkayan/kayan/core/session"
	waproto "github.com/go-webauthn/webauthn/protocol"
	"github.com/google/uuid"
)

// ---------- In-memory IdentityStorage ----------

type memRepo struct {
	mu         sync.RWMutex
	identities map[string]any
	creds      map[string]*identity.Credential
}

func newMemRepo() *memRepo {
	return &memRepo{
		identities: make(map[string]any),
		creds:      make(map[string]*identity.Credential),
	}
}

func (r *memRepo) CreateIdentity(ident any) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if fi, ok := ident.(flow.FlowIdentity); ok {
		r.identities[fmt.Sprintf("%v", fi.GetID())] = ident
	}
	if cs, ok := ident.(flow.CredentialSource); ok {
		for _, c := range cs.GetCredentials() {
			cp := c
			r.creds[c.Identifier+":"+c.Type] = &cp
		}
	}
	return nil
}

func (r *memRepo) GetIdentity(factory func() any, id any) (any, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	v, ok := r.identities[fmt.Sprintf("%v", id)]
	if !ok {
		return nil, errors.New("identity not found")
	}
	return v, nil
}

func (r *memRepo) FindIdentity(factory func() any, query map[string]any) (any, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	for _, ident := range r.identities {
		v := reflect.ValueOf(ident)
		if v.Kind() == reflect.Ptr {
			v = v.Elem()
		}
		match := true
		for field, value := range query {
			f := v.FieldByName(field)
			if !f.IsValid() || fmt.Sprintf("%v", f.Interface()) != fmt.Sprintf("%v", value) {
				match = false
				break
			}
		}
		if match {
			return ident, nil
		}
	}
	return nil, errors.New("identity not found")
}

func (r *memRepo) ListIdentities(factory func() any, page, limit int) ([]any, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]any, 0, len(r.identities))
	for _, v := range r.identities {
		out = append(out, v)
	}
	return out, nil
}

func (r *memRepo) UpdateIdentity(ident any) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if fi, ok := ident.(flow.FlowIdentity); ok {
		r.identities[fmt.Sprintf("%v", fi.GetID())] = ident
	}
	return nil
}

func (r *memRepo) DeleteIdentity(factory func() any, id any) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.identities, fmt.Sprintf("%v", id))
	return nil
}

func (r *memRepo) CreateCredential(cred any) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if c, ok := cred.(*identity.Credential); ok {
		r.creds[c.Identifier+":"+c.Type] = c
	}
	return nil
}

func (r *memRepo) GetCredentialByIdentifier(identifier, method string) (*identity.Credential, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	if method == "" {
		for key, c := range r.creds {
			if strings.HasPrefix(key, identifier+":") {
				return c, nil
			}
		}
		return nil, errors.New("credential not found")
	}
	c, ok := r.creds[identifier+":"+method]
	if !ok {
		return nil, errors.New("credential not found")
	}
	return c, nil
}

func (r *memRepo) UpdateCredentialSecret(_ context.Context, identityID, method, secret string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, c := range r.creds {
		if c.IdentityID == identityID && c.Type == method {
			c.Secret = secret
			return nil
		}
	}
	return errors.New("credential not found")
}

// ---------- In-memory WebAuthnSessionStore ----------

type memWASessionStore struct {
	mu       sync.Mutex
	sessions map[string]*flow.WebAuthnSessionData
}

func newMemWASessionStore() *memWASessionStore {
	return &memWASessionStore{sessions: make(map[string]*flow.WebAuthnSessionData)}
}

func (s *memWASessionStore) SaveSession(_ context.Context, id string, data *flow.WebAuthnSessionData) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sessions[id] = data
	return nil
}

func (s *memWASessionStore) GetSession(_ context.Context, id string) (*flow.WebAuthnSessionData, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	d, ok := s.sessions[id]
	if !ok {
		return nil, errors.New("session not found")
	}
	return d, nil
}

func (s *memWASessionStore) DeleteSession(_ context.Context, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.sessions, id)
	return nil
}

// ---------- Server ----------

type server struct {
	repo     *memRepo
	wa       *flow.WebAuthnStrategy
	sessions *session.JWTStrategy
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

func corsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		origin := envOr("ORIGIN", "http://localhost:5173")
		w.Header().Set("Access-Control-Allow-Origin", origin)
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func bearerToken(r *http.Request) string {
	parts := strings.SplitN(r.Header.Get("Authorization"), " ", 2)
	if len(parts) == 2 && parts[0] == "Bearer" {
		return parts[1]
	}
	return ""
}

// POST /api/webauthn/register/begin – { email } → CredentialCreationOptions + session_id
func (s *server) handleRegisterBegin(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Email string `json:"email"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.Email == "" {
		writeError(w, http.StatusBadRequest, "email required")
		return
	}

	// Look for an existing identity with this email; auto-create if absent.
	var ident *identity.Identity
	allIdents, _ := s.repo.ListIdentities(func() any { return &identity.Identity{} }, 1, 1000)
	for _, raw := range allIdents {
		if i, ok := raw.(*identity.Identity); ok {
			var m map[string]any
			if json.Unmarshal(i.Traits, &m) == nil && m["email"] == body.Email {
				ident = i
				break
			}
		}
	}
	if ident == nil {
		ident = &identity.Identity{
			ID:     uuid.New().String(),
			Traits: identity.JSON(fmt.Sprintf(`{"email":%q}`, body.Email)),
		}
		_ = s.repo.CreateIdentity(ident)
	}

	// WebAuthnStrategy.BeginRegistration returns CredentialCreationOptions + session ID.
	opts, sessionID, err := s.wa.BeginRegistration(r.Context(), ident, body.Email, body.Email)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "begin registration failed: "+err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"session_id": sessionID, "options": opts})
}

// POST /api/webauthn/register/finish – { email, session_id, credential } → { ok }
func (s *server) handleRegisterFinish(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Email      string          `json:"email"`
		SessionID  string          `json:"session_id"`
		Credential json.RawMessage `json:"credential"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.Email == "" || body.SessionID == "" {
		writeError(w, http.StatusBadRequest, "email, session_id and credential required")
		return
	}

	parsed, err := waproto.ParseCredentialCreationResponseBody(strings.NewReader(string(body.Credential)))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid credential: "+err.Error())
		return
	}

	var ident *identity.Identity
	allIdents, _ := s.repo.ListIdentities(func() any { return &identity.Identity{} }, 1, 1000)
	for _, raw := range allIdents {
		if i, ok := raw.(*identity.Identity); ok {
			var m map[string]any
			if json.Unmarshal(i.Traits, &m) == nil && m["email"] == body.Email {
				ident = i
				break
			}
		}
	}
	if ident == nil {
		writeError(w, http.StatusNotFound, "identity not found — call register/begin first")
		return
	}

	// FinishRegistration verifies attestation and persists the passkey credential.
	_, err = s.wa.FinishRegistration(r.Context(), ident, body.SessionID, body.Email, body.Email, parsed)
	if err != nil {
		writeError(w, http.StatusBadRequest, "registration failed: "+err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

// POST /api/webauthn/login/begin – { email } → CredentialRequestOptions + session_id
func (s *server) handleLoginBegin(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Email string `json:"email"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.Email == "" {
		writeError(w, http.StatusBadRequest, "email required")
		return
	}

	opts, sessionID, err := s.wa.BeginLogin(r.Context(), body.Email)
	if err != nil {
		writeError(w, http.StatusNotFound, "no passkey registered: "+err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"session_id": sessionID, "options": opts})
}

// POST /api/webauthn/login/finish – { email, session_id, assertion } → { session_token }
func (s *server) handleLoginFinish(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Email     string          `json:"email"`
		SessionID string          `json:"session_id"`
		Assertion json.RawMessage `json:"assertion"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.Email == "" || body.SessionID == "" {
		writeError(w, http.StatusBadRequest, "email, session_id and assertion required")
		return
	}

	parsed, err := waproto.ParseCredentialRequestResponseBody(strings.NewReader(string(body.Assertion)))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid assertion: "+err.Error())
		return
	}

	// FinishLogin verifies the cryptographic assertion against the stored public key.
	identRaw, err := s.wa.FinishLogin(r.Context(), body.Email, body.SessionID, parsed)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "authentication failed: "+err.Error())
		return
	}

	ident := identRaw.(*identity.Identity)
	sess, err := s.sessions.Create(uuid.New().String(), ident.ID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "session error")
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"session_token": sess.ID})
}

// GET /api/me – Authorization: Bearer <session_token>
func (s *server) handleMe(w http.ResponseWriter, r *http.Request) {
	token := bearerToken(r)
	sess, err := s.sessions.Validate(token)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "invalid or expired session")
		return
	}
	identRaw, err := s.repo.GetIdentity(func() any { return &identity.Identity{} }, sess.IdentityID)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "identity not found")
		return
	}
	ident := identRaw.(*identity.Identity)
	var email string
	var m map[string]any
	if json.Unmarshal(ident.Traits, &m) == nil {
		email, _ = m["email"].(string)
	}
	writeJSON(w, http.StatusOK, map[string]any{"id": ident.ID, "email": email})
}

// ---------- Main ----------

func main() {
	repo := newMemRepo()
	waStore := newMemWASessionStore()
	factory := func() any { return &identity.Identity{} }

	rpid := envOr("RPID", "localhost")
	origin := envOr("ORIGIN", "http://localhost:5173")

	// flow.NewWebAuthnStrategy wires up the real WebAuthn library with Kayan storage.
	waStrategy, err := flow.NewWebAuthnStrategy(repo, flow.WebAuthnConfig{
		RPDisplayName: "Kayan WebAuthn Example",
		RPID:          rpid,
		RPOrigins:     []string{origin},
		SessionTTL:    5 * time.Minute,
	}, factory, waStore)
	if err != nil {
		log.Fatalf("failed to create WebAuthn strategy: %v", err)
	}
	waStrategy.SetIDGenerator(func() any { return uuid.New().String() })

	jwtStrategy := session.NewHS256Strategy("change-me-in-production", 24*time.Hour)

	srv := &server{repo: repo, wa: waStrategy, sessions: jwtStrategy}

	mux := http.NewServeMux()
	mux.HandleFunc("POST /api/webauthn/register/begin", srv.handleRegisterBegin)
	mux.HandleFunc("POST /api/webauthn/register/finish", srv.handleRegisterFinish)
	mux.HandleFunc("POST /api/webauthn/login/begin", srv.handleLoginBegin)
	mux.HandleFunc("POST /api/webauthn/login/finish", srv.handleLoginFinish)
	mux.HandleFunc("GET /api/me", srv.handleMe)

	log.Printf("04-webauthn backend listening on :8080 (RPID=%s ORIGIN=%s)", rpid, origin)
	if err := http.ListenAndServe(":8080", corsMiddleware(mux)); err != nil {
		log.Fatal(err)
	}
}
