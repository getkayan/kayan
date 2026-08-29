// 02-magic-link: Passwordless magic-link authentication backed by Kayan.
//
// Demonstrates:
//   - flow.NewMagicLinkStrategy() with an in-memory TokenStore
//   - Two-step login: POST /api/magic/initiate → GET /api/magic/verify
//   - JWT session via session.NewHS256Strategy()
//   - GET /api/me protected endpoint
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

// ---------- In-memory IdentityStorage ----------

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

// ---------- Magic-link registration strategy (auto-create on first initiation) ----------

type magicLinkRegStrategy struct {
	repo *kayantesting.MemoryStore
}

func (s *magicLinkRegStrategy) ID() string { return "magic_link" }

func (s *magicLinkRegStrategy) Register(_ context.Context, traits identity.JSON, _ string) (any, error) {
	ctx := context.Background()
	ident := &identity.Identity{
		ID:     uuid.New().String(),
		Traits: traits,
	}
	var m map[string]any
	if err := json.Unmarshal(traits, &m); err != nil {
		return nil, err
	}
	email, _ := m["email"].(string)
	ident.Credentials = []identity.Credential{{
		ID:         uuid.New().String(),
		IdentityID: ident.ID,
		Type:       "magic_link",
		Identifier: email,
	}}
	if err := s.repo.CreateIdentity(ctx, ident); err != nil {
		return nil, err
	}
	for _, c := range ident.Credentials {
		cp := c
		_ = s.repo.CreateCredential(ctx, &cp)
	}
	return ident, nil
}

// ---------- Server ----------

type server struct {
	repo     *kayantesting.MemoryStore
	magic    *flow.MagicLinkStrategy
	reg      *flow.RegistrationManager
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

// POST /api/magic/initiate – { email } → generates token, logs link to stdout.
func (s *server) handleInitiate(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var body struct {
		Email string `json:"email"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.Email == "" {
		writeError(w, http.StatusBadRequest, "email required")
		return
	}

	// Auto-create identity on first initiation.
	if _, err := s.repo.GetCredentialByIdentifier(ctx, body.Email, "magic_link"); err != nil {
		_, err := s.reg.Submit(r.Context(), "magic_link",
			identity.JSON(fmt.Sprintf(`{"email":%q}`, body.Email)), "")
		if err != nil {
			writeError(w, http.StatusInternalServerError, "failed to create identity")
			return
		}
	}

	// MagicLinkStrategy.Initiate stores the single-use token in the TokenStore.
	tokenRaw, err := s.magic.Initiate(r.Context(), body.Email)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to generate magic link")
		return
	}

	authToken := tokenRaw.(*domain.AuthToken)
	log.Printf("[MAGIC LINK] To: %s | Link: http://localhost:5173/verify?token=%s",
		body.Email, authToken.Token)

	writeJSON(w, http.StatusOK, map[string]string{
		"message": "magic link sent (token logged to stdout in this demo)",
	})
}

// GET /api/magic/verify?token=<t> – validates token, issues JWT session.
func (s *server) handleVerify(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	token := r.URL.Query().Get("token")
	if token == "" {
		writeError(w, http.StatusBadRequest, "token required")
		return
	}

	// MagicLinkStrategy.Authenticate checks expiry, verifies type, and consumes the token.
	identRaw, err := s.magic.Authenticate(r.Context(), "", token)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "invalid or expired magic link")
		return
	}

	ident := identRaw.(*identity.Identity)
	sess, err := s.sessions.Create(ctx, uuid.New().String(), ident.ID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not create session")
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{"session_token": sess.ID})
}

// GET /api/me – Authorization: Bearer <token> → { id, email }
func (s *server) handleMe(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	token := bearerToken(r)
	if token == "" {
		writeError(w, http.StatusUnauthorized, "missing token")
		return
	}

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
	writeJSON(w, http.StatusOK, map[string]string{"id": ident.ID, "email": email})
}

// ---------- Main ----------

func main() {
	repo := kayantesting.NewMemoryStore()
	tokenStore := newMemTokenStore()
	factory := func() any { return &identity.Identity{} }

	magicStrategy := flow.NewMagicLinkStrategy(repo, tokenStore)

	reg := flow.NewRegistrationManager(repo, factory)
	reg.RegisterStrategy(&magicLinkRegStrategy{repo: repo})

	jwtStrategy := session.NewHS256Strategy(sessionSecret(), 24*time.Hour)

	srv := &server{
		repo:     repo,
		magic:    magicStrategy,
		reg:      reg,
		sessions: jwtStrategy,
	}

	mux := http.NewServeMux()
	mux.HandleFunc("POST /api/magic/initiate", srv.handleInitiate)
	mux.HandleFunc("GET /api/magic/verify", srv.handleVerify)
	mux.HandleFunc("GET /api/me", srv.handleMe)

	log.Println("02-magic-link backend listening on :8080")
	log.Println("Magic links are printed to stdout — check the console after initiating.")
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
