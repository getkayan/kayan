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
	"github.com/getkayan/kayan/core/flow"
	"github.com/getkayan/kayan/core/identity"
	"github.com/getkayan/kayan/core/session"
	kayantesting "github.com/getkayan/kayan/kayan-testing"
	waproto "github.com/go-webauthn/webauthn/protocol"
	"github.com/google/uuid"
	"log"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

// ---------- In-memory IdentityStorage ----------

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
	repo     *kayantesting.MemoryStore
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
	ctx := r.Context()
	var body struct {
		Email string `json:"email"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.Email == "" {
		writeError(w, http.StatusBadRequest, "email required")
		return
	}

	// Look for an existing identity with this email; auto-create if absent.
	var ident *identity.Identity
	allIdents, _ := s.repo.ListIdentities(ctx, func() any { return &identity.Identity{} }, 1, 1000)
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
		_ = s.repo.CreateIdentity(ctx, ident)
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
	ctx := r.Context()
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
	allIdents, _ := s.repo.ListIdentities(ctx, func() any { return &identity.Identity{} }, 1, 1000)
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
	ctx := r.Context()
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
	sess, err := s.sessions.Create(ctx, uuid.New().String(), ident.ID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "session error")
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"session_token": sess.ID})
}

// GET /api/me – Authorization: Bearer <session_token>
func (s *server) handleMe(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	token := bearerToken(r)
	sess, err := s.sessions.Validate(ctx, token)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "invalid or expired session")
		return
	}
	identRaw, err := s.repo.GetIdentity(ctx, func() any { return &identity.Identity{} }, sess.IdentityID)
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
	repo := kayantesting.NewMemoryStore()
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

	jwtStrategy := session.NewHS256Strategy(sessionSecret(), 24*time.Hour)

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

// sessionSecret reads the signing secret from the environment.
//
// Examples used to hardcode one. That string is the most-copied line in a
// sample application, and it ends up signing real sessions.
func sessionSecret() string {
	secret := os.Getenv("SESSION_SECRET")
	if secret == "" {
		log.Fatal("SESSION_SECRET is not set. Generate one with: openssl rand -base64 32")
	}
	return secret
}
