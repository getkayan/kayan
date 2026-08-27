// 09-email-otp: Passwordless email one-time password authentication backed by Kayan.
//
// Demonstrates:
//   - flow.NewOTPStrategy() with a custom OTPSender (logs to stdout, simulating email)
//   - Auto-registration on first /api/otp/send if the email address is new
//   - flow.LoginManager.InitiateLogin() to generate and deliver the OTP
//   - flow.LoginManager.Authenticate() to verify the code
//   - JWT session via session.NewHS256Strategy()
//
// Endpoints:
//   - POST /api/otp/send   – { email } → triggers OTP delivery (code printed to stdout)
//   - POST /api/otp/verify – { email, code } → { session_token }
//   - GET  /api/me         – Authorization: Bearer <session_token>
package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/getkayan/kayan/core/domain"
	"github.com/getkayan/kayan/core/flow"
	"github.com/getkayan/kayan/core/identity"
	"github.com/getkayan/kayan/core/session"
	kayantesting "github.com/getkayan/kayan/kayan-testing"
	"github.com/google/uuid"
	"log"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

// ---------- stdoutEmailSender – demo OTPSender that prints the code ----------

type stdoutEmailSender struct{}

func (s *stdoutEmailSender) Send(_ context.Context, recipient, code string) error {
	log.Printf("[EMAIL] To: %s  Subject: Your login code  Body: %s", recipient, code)
	return nil
}

// ---------- In-memory TokenStore ----------

type memTokenStore struct {
	mu     sync.Mutex
	tokens map[string]*domain.AuthToken
}

func newMemTokenStore() *memTokenStore {
	return &memTokenStore{tokens: make(map[string]*domain.AuthToken)}
}

func (s *memTokenStore) SaveToken(_ context.Context, t *domain.AuthToken) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.tokens[t.Token] = t
	return nil
}

func (s *memTokenStore) GetToken(_ context.Context, token string) (*domain.AuthToken, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	t, ok := s.tokens[token]
	if !ok {
		return nil, errors.New("token not found")
	}
	return t, nil
}

func (s *memTokenStore) ConsumeToken(_ context.Context, token, tokenType string) (*domain.AuthToken, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	t, ok := s.tokens[token]
	if !ok || t.Type != tokenType || !time.Now().Before(t.ExpiresAt) {
		return nil, errors.New("token not found or expired")
	}
	delete(s.tokens, token)
	return t, nil
}

func (s *memTokenStore) DeleteToken(_ context.Context, token string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.tokens, token)
	return nil
}

func (s *memTokenStore) DeleteExpiredTokens(_ context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	for k, t := range s.tokens {
		if t.ExpiresAt.Before(now) {
			delete(s.tokens, k)
		}
	}
	return nil
}

// ---------- In-memory IdentityStorage ----------

type memRepo struct {
	// The storage contract comes from the shared in-memory store, which is
	// verified by kayantesting.StorageSuite. Only the strategy-specific
	// methods below are written here.
	*kayantesting.MemoryStore

	mu         sync.RWMutex
	identities map[string]any
	creds      map[string]*identity.Credential
}

func newMemRepo() *memRepo {
	return &memRepo{
		MemoryStore: kayantesting.NewMemoryStore(),
		identities:  make(map[string]any),
		creds:       make(map[string]*identity.Credential),
	}
}

// ensureIdentity auto-creates an identity + "otp" credential for the email address
// if one does not already exist.
func (r *memRepo) ensureIdentity(email string) {
	ctx := context.Background()
	if _, err := r.GetCredentialByIdentifier(ctx, email, "otp"); err == nil {
		return
	}
	id := uuid.New().String()
	ident := &identity.Identity{
		ID:     id,
		Traits: identity.JSON(fmt.Sprintf(`{"email":%q}`, email)),
	}
	_ = r.CreateIdentity(ctx, ident)
	cred := &identity.Credential{
		IdentityID: id,
		Type:       "otp",
		Identifier: email,
	}
	_ = r.CreateCredential(ctx, cred)
}

// ---------- Server ----------

type server struct {
	repo     *memRepo
	login    *flow.LoginManager
	sessions *session.JWTStrategy
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
		w.Header().Set("Access-Control-Allow-Origin", "http://localhost:5173")
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

// POST /api/otp/send – { email }
// Auto-registers the email on first call, then sends the OTP via stdoutEmailSender.
func (s *server) handleSend(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Email string `json:"email"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.Email == "" {
		writeError(w, http.StatusBadRequest, "email required")
		return
	}

	// Auto-create identity+credential for new email addresses.
	s.repo.ensureIdentity(body.Email)

	// OTPStrategy.Initiate generates a 6-digit code, stores it, and calls OTPSender.Send.
	if _, err := s.login.InitiateLogin(r.Context(), "otp", body.Email); err != nil {
		writeError(w, http.StatusInternalServerError, "failed to send OTP: "+err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "code sent (check server log)"})
}

// POST /api/otp/verify – { email, code } → { session_token }
func (s *server) handleVerify(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var body struct {
		Email string `json:"email"`
		Code  string `json:"code"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.Email == "" || body.Code == "" {
		writeError(w, http.StatusBadRequest, "email and code required")
		return
	}

	identRaw, err := s.login.Authenticate(r.Context(), "otp", body.Email, body.Code)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "invalid or expired code")
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
	repo := newMemRepo()
	tokenStore := newMemTokenStore()
	factory := func() any { return &identity.Identity{} }

	// OTPStrategy: generate codes, store in tokenStore, deliver via stdoutEmailSender.
	otpStrategy := flow.NewOTPStrategy(repo, tokenStore, &stdoutEmailSender{})

	login := flow.NewLoginManager(repo, factory)
	login.RegisterStrategy(otpStrategy)

	jwtStrategy := session.NewHS256Strategy(sessionSecret(), 24*time.Hour)

	srv := &server{repo: repo, login: login, sessions: jwtStrategy}

	mux := http.NewServeMux()
	mux.HandleFunc("POST /api/otp/send", srv.handleSend)
	mux.HandleFunc("POST /api/otp/verify", srv.handleVerify)
	mux.HandleFunc("GET /api/me", srv.handleMe)

	log.Println("09-email-otp backend listening on :8080")
	if err := http.ListenAndServe(":8080", corsMiddleware(mux)); err != nil {
		log.Fatal(err)
	}
}

// sessionSecret reads the session signing secret from the environment.
//
// Examples used to hardcode one. That string is the most-copied line in a
// sample application, and a copied secret ends up signing real sessions.
func sessionSecret() string {
	secret := os.Getenv("SESSION_SECRET")
	if secret == "" {
		log.Fatal("SESSION_SECRET is not set. Generate one with: openssl rand -base64 32")
	}
	return secret
}
