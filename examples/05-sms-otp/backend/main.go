// 05-sms-otp: Passwordless SMS one-time password authentication backed by Kayan.
//
// Demonstrates:
//   - flow.NewOTPStrategy() with a custom OTPSender (logs to stdout, simulating SMS)
//   - Auto-registration on first /api/sms/initiate if the phone number is new
//   - flow.LoginManager.InitiateLogin() to trigger code delivery
//   - flow.LoginManager.Authenticate() to verify the code
//   - JWT session via session.NewHS256Strategy()
//
// Endpoints:
//   - POST /api/sms/initiate – { phone } → triggers OTP send (code printed to stdout)
//   - POST /api/sms/verify   – { phone, code } → { session_token }
//   - GET  /api/me           – Authorization: Bearer <session_token>
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
	// kayantesting.MemoryStore keeps everything in process memory and loses it
	// on restart. It is what lets this example run with no database; a real
	// deployment uses kayan-gorm or another persistent adapter.
	kayantesting "github.com/getkayan/kayan/kayan-testing"
	"github.com/google/uuid"
	"log"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

// ---------- stdoutSMSSender – demo OTPSender that prints the code ----------

type stdoutSMSSender struct{}

func (s *stdoutSMSSender) Send(_ context.Context, recipient, code string) error {
	log.Printf("[SMS] To: %s  Code: %s", recipient, code)
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

// ensureIdentity auto-creates an identity + "otp" credential for the phone number
// if one does not already exist. The OTPStrategy requires a credential to exist
// before it can deliver a code.
func (r *memRepo) ensureIdentity(phone string) {
	ctx := context.Background()
	if _, err := r.GetCredentialByIdentifier(ctx, phone, "otp"); err == nil {
		return // already registered
	}
	id := uuid.New().String()
	ident := &identity.Identity{
		ID:     id,
		Traits: identity.JSON(fmt.Sprintf(`{"phone":%q}`, phone)),
	}
	_ = r.CreateIdentity(ctx, ident)
	cred := &identity.Credential{
		IdentityID: id,
		Type:       "otp",
		Identifier: phone,
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

// POST /api/sms/initiate – { phone }
// Auto-registers the phone number on first call, then sends the OTP.
func (s *server) handleInitiate(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Phone string `json:"phone"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.Phone == "" {
		writeError(w, http.StatusBadRequest, "phone required")
		return
	}

	// Auto-create identity+credential for new phone numbers.
	s.repo.ensureIdentity(body.Phone)

	// OTPStrategy.Initiate generates a code, stores it, and calls OTPSender.Send.
	if _, err := s.login.InitiateLogin(r.Context(), "otp", body.Phone); err != nil {
		writeError(w, http.StatusInternalServerError, "failed to send OTP: "+err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "code sent (check server log)"})
}

// POST /api/sms/verify – { phone, code } → { session_token }
func (s *server) handleVerify(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var body struct {
		Phone string `json:"phone"`
		Code  string `json:"code"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.Phone == "" || body.Code == "" {
		writeError(w, http.StatusBadRequest, "phone and code required")
		return
	}

	identRaw, err := s.login.Authenticate(r.Context(), "otp", body.Phone, body.Code)
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
	var phone string
	var m map[string]any
	if json.Unmarshal(ident.Traits, &m) == nil {
		phone, _ = m["phone"].(string)
	}
	writeJSON(w, http.StatusOK, map[string]any{"id": ident.ID, "phone": phone})
}

// ---------- Main ----------

func main() {
	repo := newMemRepo()
	tokenStore := newMemTokenStore()
	factory := func() any { return &identity.Identity{} }

	// OTPStrategy: generate codes, store in tokenStore, deliver via stdoutSMSSender.
	otpStrategy := flow.NewOTPStrategy(repo, tokenStore, &stdoutSMSSender{})

	login := flow.NewLoginManager(repo, factory)
	login.RegisterStrategy(otpStrategy)

	jwtStrategy := session.NewHS256Strategy(sessionSecret(), 24*time.Hour)

	srv := &server{repo: repo, login: login, sessions: jwtStrategy}

	mux := http.NewServeMux()
	mux.HandleFunc("POST /api/sms/initiate", srv.handleInitiate)
	mux.HandleFunc("POST /api/sms/verify", srv.handleVerify)
	mux.HandleFunc("GET /api/me", srv.handleMe)

	log.Println("05-sms-otp backend listening on :8080")
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
