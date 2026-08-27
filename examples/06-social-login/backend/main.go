// 06-social-login: GitHub OAuth2 social login backed by Kayan.
//
// Demonstrates:
//   - A custom GitHubStrategy implementing flow.LoginStrategy + flow.Initiator
//   - CSRF protection via single-use state tokens stored in domain.TokenStore
//   - Find-or-create identity on GitHub callback using the repo
//   - JWT session via session.NewHS256Strategy()
//
// Set GITHUB_CLIENT_ID and GITHUB_CLIENT_SECRET environment variables before running.
// The GitHub OAuth App callback URL must be set to http://localhost:5173/callback
// (or match GITHUB_REDIRECT_URI).
//
// Endpoints:
//   - GET  /api/oauth/github/start    → redirects browser to GitHub authorization page
//   - GET  /api/oauth/github/callback → exchanges code for token, issues session_token
//   - GET  /api/me                    → Authorization: Bearer <session_token>
package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/getkayan/kayan/core/domain"
	"github.com/getkayan/kayan/core/flow"
	"github.com/getkayan/kayan/core/identity"
	"github.com/getkayan/kayan/core/session"
	kayantesting "github.com/getkayan/kayan/kayan-testing"
	"github.com/google/uuid"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/github"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"
)

// ---------- In-memory TokenStore (for OAuth2 state CSRF tokens) ----------

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

// findOrCreateBySub finds an existing identity whose GitHub sub matches, or creates one.
func (r *memRepo) findOrCreateBySub(sub, email, login string) *identity.Identity {
	ctx := context.Background()
	// Look for existing credential with this sub.
	if cred, err := r.GetCredentialByIdentifier(ctx, sub, "github"); err == nil {
		if identRaw, err := r.GetIdentity(ctx, func() any { return &identity.Identity{} }, cred.IdentityID); err == nil {
			if ident, ok := identRaw.(*identity.Identity); ok {
				return ident
			}
		}
	}
	// Create new identity.
	id := uuid.New().String()
	traitsJSON := fmt.Sprintf(`{"email":%q,"login":%q,"provider":"github"}`, email, login)
	ident := &identity.Identity{
		ID:     id,
		Traits: identity.JSON(traitsJSON),
	}
	_ = r.CreateIdentity(ctx, ident)
	cred := &identity.Credential{
		IdentityID: id,
		Type:       "github",
		Identifier: sub,
	}
	_ = r.CreateCredential(ctx, cred)
	return ident
}

// ---------- GitHubStrategy – implements flow.LoginStrategy + flow.Initiator ----------

// GitHubStrategy authenticates users via GitHub OAuth2.
// It implements flow.LoginStrategy (ID, Authenticate) and flow.Initiator (Initiate).
//
// Initiate(ctx, "") → stores a random state token, returns the GitHub auth URL.
// Authenticate(ctx, code, state) → validates state, exchanges code, fetches /user,
// find-or-creates the identity in the repo, and returns it.
type GitHubStrategy struct {
	oauth2Cfg  *oauth2.Config
	tokenStore *memTokenStore
	repo       *memRepo
	stateTTL   time.Duration
}

func newGitHubStrategy(cfg *oauth2.Config, tokenStore *memTokenStore, repo *memRepo) *GitHubStrategy {
	return &GitHubStrategy{
		oauth2Cfg:  cfg,
		tokenStore: tokenStore,
		repo:       repo,
		stateTTL:   10 * time.Minute,
	}
}

func (s *GitHubStrategy) ID() string { return "github" }

// Initiate generates a CSRF state token and returns the GitHub authorization URL.
func (s *GitHubStrategy) Initiate(ctx context.Context, _ string) (any, error) {
	rawState := make([]byte, 32)
	if _, err := rand.Read(rawState); err != nil {
		return nil, fmt.Errorf("github: failed to generate state: %w", err)
	}
	state := hex.EncodeToString(rawState)

	if err := s.tokenStore.SaveToken(ctx, &domain.AuthToken{
		Token:     state,
		Type:      "oauth2_state",
		ExpiresAt: time.Now().Add(s.stateTTL),
	}); err != nil {
		return nil, fmt.Errorf("github: failed to store state: %w", err)
	}

	authURL := s.oauth2Cfg.AuthCodeURL(state, oauth2.AccessTypeOnline)
	return authURL, nil
}

// Authenticate verifies the state, exchanges the code for a GitHub token,
// fetches the authenticated user's profile, and returns the Kayan identity.
// identifier = state, secret = code (both come from the callback query params).
func (s *GitHubStrategy) Authenticate(ctx context.Context, state, code string) (any, error) {
	// Validate state (CSRF) – single-use.
	stateToken, err := s.tokenStore.GetToken(ctx, state)
	if err != nil || stateToken.Type != "oauth2_state" || stateToken.ExpiresAt.Before(time.Now()) {
		return nil, errors.New("github: invalid or expired state")
	}
	_ = s.tokenStore.DeleteToken(ctx, state)

	// Exchange authorization code for access token.
	tok, err := s.oauth2Cfg.Exchange(ctx, code)
	if err != nil {
		return nil, fmt.Errorf("github: token exchange failed: %w", err)
	}

	// Fetch GitHub user profile.
	client := s.oauth2Cfg.Client(ctx, tok)
	resp, err := client.Get("https://api.github.com/user")
	if err != nil {
		return nil, fmt.Errorf("github: failed to fetch user: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("github: failed to read user response: %w", err)
	}

	var ghUser struct {
		ID    int64  `json:"id"`
		Login string `json:"login"`
		Email string `json:"email"`
	}
	if err := json.Unmarshal(body, &ghUser); err != nil {
		return nil, fmt.Errorf("github: failed to parse user: %w", err)
	}

	sub := fmt.Sprintf("%d", ghUser.ID)
	ident := s.repo.findOrCreateBySub(sub, ghUser.Email, ghUser.Login)
	return ident, nil
}

// ---------- Server ----------

type server struct {
	login    *flow.LoginManager
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

// GET /api/oauth/github/start → redirects to GitHub
func (s *server) handleStart(w http.ResponseWriter, r *http.Request) {
	// GitHubStrategy.Initiate returns the GitHub authorization URL.
	result, err := s.login.InitiateLogin(r.Context(), "github", "")
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to start OAuth2: "+err.Error())
		return
	}
	authURL, ok := result.(string)
	if !ok {
		writeError(w, http.StatusInternalServerError, "unexpected initiate result")
		return
	}
	http.Redirect(w, r, authURL, http.StatusFound)
}

// GET /api/oauth/github/callback?code=&state= → { session_token }
func (s *server) handleCallback(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	state := r.URL.Query().Get("state")
	code := r.URL.Query().Get("code")
	if state == "" || code == "" {
		writeError(w, http.StatusBadRequest, "state and code required")
		return
	}

	// GitHubStrategy.Authenticate validates state, exchanges code, returns identity.
	identRaw, err := s.login.Authenticate(r.Context(), "github", state, code)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "GitHub authentication failed: "+err.Error())
		return
	}

	ident := identRaw.(*identity.Identity)
	sess, err := s.sessions.Create(ctx, uuid.New().String(), ident.ID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "session error")
		return
	}

	// For SPA frontends: redirect with token in hash fragment (or return JSON).
	frontendURL := envOr("FRONTEND_URL", "http://localhost:5173")
	http.Redirect(w, r, frontendURL+"/?token="+url.QueryEscape(sess.ID), http.StatusFound)
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
	// repo is embedded in the GitHubStrategy; access it via the server's repo field.
	// We store repo on server for /api/me lookups.
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{"id": sess.IdentityID})
}

// ---------- Main ----------

func main() {
	repo := newMemRepo()
	tokenStore := newMemTokenStore()
	factory := func() any { return &identity.Identity{} }

	redirectURI := envOr("GITHUB_REDIRECT_URI", "http://localhost:8080/api/oauth/github/callback")

	oauth2Cfg := &oauth2.Config{
		ClientID:     envOr("GITHUB_CLIENT_ID", "YOUR_CLIENT_ID"),
		ClientSecret: envOr("GITHUB_CLIENT_SECRET", "YOUR_CLIENT_SECRET"),
		RedirectURL:  redirectURI,
		Scopes:       []string{"user:email", "read:user"},
		Endpoint:     github.Endpoint,
	}

	ghStrategy := newGitHubStrategy(oauth2Cfg, tokenStore, repo)

	// Wrap GitHubStrategy in a Kayan LoginManager.
	login := flow.NewLoginManager(repo, factory)
	login.RegisterStrategy(ghStrategy)

	jwtStrategy := session.NewHS256Strategy(sessionSecret(), 24*time.Hour)

	srv := &server{login: login, sessions: jwtStrategy}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/oauth/github/start", srv.handleStart)
	mux.HandleFunc("GET /api/oauth/github/callback", srv.handleCallback)
	mux.HandleFunc("GET /api/me", srv.handleMe)

	log.Println("06-social-login backend listening on :8080")
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
