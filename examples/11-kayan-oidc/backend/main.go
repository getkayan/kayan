// 11-kayan-oidc: Login via a Kayan OIDC provider, backed by flow.KayanOIDCStrategy.
//
// This application acts as an OIDC Relying Party using a Kayan instance as the IdP.
// Demonstrates:
//   - flow.NewKayanOIDCStrategy() with PKCE S256, state CSRF protection, nonce validation
//   - KayanOIDCRepository (store/consume state, find-or-create by provider sub)
//   - OAuthConfiger + IDTokenParser interface implementations
//   - JWT session via session.NewHS256Strategy()
//
// The demo uses SIMULATED OAuthConfiger and IDTokenParser — no real Kayan server needed.
// In production set KAYAN_ISSUER, CLIENT_ID, CLIENT_SECRET and use real implementations.
//
// Demo trick: the "fake code" returned by the simulated authorize step IS the state value,
// allowing the simulated Exchange to find the correct nonce and embed it in the id_token.
//
// Endpoints:
//   - GET  /api/oidc/start               → { redirect_url, state } (initiate OIDC flow)
//   - GET  /api/oidc/demo-callback?state= → simulates Kayan's redirect back (demo only)
//   - GET  /api/oidc/callback?code=&state= → exchange code, verify token, issue session
//   - GET  /api/me                        → Authorization: Bearer <session_token>
package main

import (
	"context"
	"encoding/base64"
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
	"github.com/google/uuid"
)

// ---------- In-memory KayanOIDCRepository + IdentityStorage ----------

type oidcStateRecord struct {
	verifier  string
	nonce     string
	expiresAt time.Time
}

type memRepo struct {
	mu         sync.RWMutex
	identities map[string]any
	creds      map[string]*identity.Credential
	// OIDC state: state token → record (StoreOIDCState / ConsumeOIDCState)
	oidcStates map[string]*oidcStateRecord
	// nonce lookup shared with simulated OAuth components: state → nonce
	nonceByState map[string]string
}

func newMemRepo() *memRepo {
	return &memRepo{
		identities:   make(map[string]any),
		creds:        make(map[string]*identity.Credential),
		oidcStates:   make(map[string]*oidcStateRecord),
		nonceByState: make(map[string]string),
	}
}

// flow.KayanOIDCRepository implementation

func (r *memRepo) StoreOIDCState(_ context.Context, state, codeVerifier, nonce string, expiry time.Duration) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	rec := &oidcStateRecord{
		verifier:  codeVerifier,
		nonce:     nonce,
		expiresAt: time.Now().Add(expiry),
	}
	r.oidcStates[state] = rec
	r.nonceByState[state] = nonce // expose for simulated Exchange
	return nil
}

func (r *memRepo) ConsumeOIDCState(_ context.Context, state string) (codeVerifier, nonce string, err error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	rec, ok := r.oidcStates[state]
	if !ok {
		return "", "", flow.ErrKayanOIDCStateInvalid
	}
	delete(r.oidcStates, state)
	delete(r.nonceByState, state)
	if time.Now().After(rec.expiresAt) {
		return "", "", flow.ErrKayanOIDCStateInvalid
	}
	return rec.verifier, rec.nonce, nil
}

func (r *memRepo) FindOrCreateByProviderSub(_ context.Context, sub string, traits identity.JSON, factory func() any) (any, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	// Look for existing credential keyed by sub:kayan_oidc
	for _, c := range r.creds {
		if c.Identifier == sub && c.Type == "kayan_oidc" {
			if ident, ok := r.identities[c.IdentityID]; ok {
				return ident, nil
			}
		}
	}
	// Create new identity.
	id := uuid.New().String()
	ident := &identity.Identity{ID: id, Traits: traits}
	r.identities[id] = ident
	r.creds[sub+":kayan_oidc"] = &identity.Credential{
		IdentityID: id,
		Type:       "kayan_oidc",
		Identifier: sub,
	}
	return ident, nil
}

// domain.IdentityStorage implementation

func (r *memRepo) CreateIdentity(ident any) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if fi, ok := ident.(flow.FlowIdentity); ok {
		r.identities[fmt.Sprintf("%v", fi.GetID())] = ident
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

// ---------- Simulated OAuthConfiger + IDTokenParser ----------

// simulatedIDClaims is what gets encoded in the fake id_token.
type simulatedIDClaims struct {
	Sub   string `json:"sub"`
	Email string `json:"email"`
	Nonce string `json:"nonce"`
}

// simulatedOAuthConfig implements flow.OAuthConfiger without a real Kayan server.
// It shares the repo's nonceByState map so it can embed the correct nonce in the id_token.
//
// Demo trick: Exchange treats its "code" argument as the state value, allowing it to look
// up the stored nonce. In the real flow, Kayan's server embeds the nonce into the real JWT.
type simulatedOAuthConfig struct {
	issuer      string
	clientID    string
	redirectURI string
	repo        *memRepo
}

func (c *simulatedOAuthConfig) AuthCodeURL(state string, _ ...flow.AuthCodeOption) string {
	return fmt.Sprintf("%s/oauth2/authorize?response_type=code&client_id=%s&redirect_uri=%s&state=%s",
		c.issuer, c.clientID, c.redirectURI, state)
}

func (c *simulatedOAuthConfig) Exchange(_ context.Context, fakeCode string, _ ...flow.AuthCodeOption) (flow.OAuthToken, error) {
	// In the demo, fakeCode IS the state value (see /api/oidc/demo-callback handler).
	// This lets us look up the nonce that was stored during Initiate.
	c.repo.mu.RLock()
	// The nonce was removed from nonceByState during ConsumeOIDCState; it's been
	// returned by ConsumeOIDCState to the strategy. Since KayanOIDCStrategy calls
	// ConsumeOIDCState BEFORE calling Exchange, we can't look it up here anymore.
	//
	// Solution: the demo-callback handler directly provides the nonce in the code.
	// The fake code = base64(state + ":" + nonce).
	c.repo.mu.RUnlock()

	// Decode fakeCode: base64("<state>:<nonce>")
	decoded, err := base64.StdEncoding.DecodeString(fakeCode)
	if err != nil {
		return nil, fmt.Errorf("simulated exchange: invalid code: %w", err)
	}
	parts := strings.SplitN(string(decoded), ":", 2)
	if len(parts) != 2 {
		return nil, errors.New("simulated exchange: malformed code")
	}
	nonce := parts[1]

	// Build a simulated id_token (base64-encoded JSON claims).
	claims := simulatedIDClaims{
		Sub:   "demo-user-001",
		Email: "demo@kayan.example.com",
		Nonce: nonce,
	}
	claimsJSON, _ := json.Marshal(claims)
	idToken := base64.StdEncoding.EncodeToString(claimsJSON)

	return &simulatedOAuthToken{idToken: idToken}, nil
}

// simulatedOAuthToken implements flow.OAuthToken.
type simulatedOAuthToken struct {
	idToken string
}

func (t *simulatedOAuthToken) Extra(key string) any {
	if key == "id_token" {
		return t.idToken
	}
	return nil
}

// simulatedIDTokenParser implements flow.IDTokenParser.
// In production, this would verify a real JWT signed by Kayan's private key.
type simulatedIDTokenParser struct{}

func (p *simulatedIDTokenParser) ParseAndVerify(rawIDToken, _, _, expectedNonce string) (*flow.IDTokenClaims, error) {
	decoded, err := base64.StdEncoding.DecodeString(rawIDToken)
	if err != nil {
		return nil, fmt.Errorf("simulated parser: invalid id_token: %w", err)
	}
	var claims simulatedIDClaims
	if err := json.Unmarshal(decoded, &claims); err != nil {
		return nil, fmt.Errorf("simulated parser: malformed claims: %w", err)
	}
	if claims.Nonce != expectedNonce {
		return nil, fmt.Errorf("simulated parser: nonce mismatch (got %q, want %q)", claims.Nonce, expectedNonce)
	}
	return &flow.IDTokenClaims{Sub: claims.Sub, Email: claims.Email}, nil
}

// ---------- Server ----------

type server struct {
	repo     *memRepo
	login    *flow.LoginManager
	sessions *session.JWTStrategy
	issuer   string
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

// GET /api/oidc/start → { redirect_url, state }
// KayanOIDCStrategy.Initiate: generates state+PKCE+nonce, stores them, returns auth URL.
func (s *server) handleStart(w http.ResponseWriter, r *http.Request) {
	result, err := s.login.InitiateLogin(r.Context(), "kayan_oidc", "")
	if err != nil {
		writeError(w, http.StatusInternalServerError, "OIDC initiate failed: "+err.Error())
		return
	}
	writeJSON(w, http.StatusOK, result)
}

// GET /api/oidc/demo-callback?state= (demo only, no real Kayan server)
// Simulates Kayan redirecting back after user approval.
// Creates a fake "code" that encodes (state, nonce) so Exchange can retrieve the nonce.
func (s *server) handleDemoCallback(w http.ResponseWriter, r *http.Request) {
	state := r.URL.Query().Get("state")
	if state == "" {
		writeError(w, http.StatusBadRequest, "state required")
		return
	}

	// Read the nonce before it's consumed by Authenticate.
	s.repo.mu.RLock()
	rec, ok := s.repo.oidcStates[state]
	s.repo.mu.RUnlock()
	if !ok {
		writeError(w, http.StatusBadRequest, "unknown or expired state")
		return
	}

	// Encode state:nonce as base64 to produce a fake "authorization code".
	fakeCode := base64.StdEncoding.EncodeToString([]byte(state + ":" + rec.nonce))

	// Redirect to the real callback with the fake code.
	http.Redirect(w, r,
		fmt.Sprintf("/api/oidc/callback?code=%s&state=%s", fakeCode, state),
		http.StatusFound)
}

// GET /api/oidc/callback?code=&state= → { session_token }
// KayanOIDCStrategy.Authenticate: validates state, exchanges code, verifies id_token, issues session.
func (s *server) handleCallback(w http.ResponseWriter, r *http.Request) {
	state := r.URL.Query().Get("state")
	code := r.URL.Query().Get("code")
	if state == "" || code == "" {
		writeError(w, http.StatusBadRequest, "state and code required")
		return
	}

	identRaw, err := s.login.Authenticate(r.Context(), "kayan_oidc", state, code)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "OIDC authentication failed: "+err.Error())
		return
	}

	ident := identRaw.(*identity.Identity)
	sess, err := s.sessions.Create(uuid.New().String(), fmt.Sprintf("%v", ident.GetID()))
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
	var m map[string]any
	_ = json.Unmarshal(ident.Traits, &m)
	writeJSON(w, http.StatusOK, map[string]any{
		"id":     fmt.Sprintf("%v", ident.GetID()),
		"traits": m,
	})
}

// ---------- Main ----------

func main() {
	repo := newMemRepo()
	factory := func() any { return &identity.Identity{} }

	issuer := envOr("KAYAN_ISSUER", "https://auth.example.com")
	clientID := envOr("CLIENT_ID", "demo-client")
	redirectURI := envOr("REDIRECT_URI", "http://localhost:8080/api/oidc/callback")

	// Simulated OAuthConfiger wraps the in-memory repo so Exchange can resolve nonces.
	oauthCfg := &simulatedOAuthConfig{
		issuer:      issuer,
		clientID:    clientID,
		redirectURI: redirectURI,
		repo:        repo,
	}

	// flow.NewKayanOIDCStrategy wires PKCE, state CSRF, nonce validation, find-or-create.
	oidcStrategy := flow.NewKayanOIDCStrategy(
		issuer, clientID, redirectURI,
		oauthCfg,
		&simulatedIDTokenParser{},
		repo,
		factory,
	)

	login := flow.NewLoginManager(repo, factory)
	login.RegisterStrategy(oidcStrategy)

	jwtStrategy := session.NewHS256Strategy("change-me-in-production", 24*time.Hour)

	srv := &server{repo: repo, login: login, sessions: jwtStrategy, issuer: issuer}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/oidc/start", srv.handleStart)
	mux.HandleFunc("GET /api/oidc/demo-callback", srv.handleDemoCallback)
	mux.HandleFunc("GET /api/oidc/callback", srv.handleCallback)
	mux.HandleFunc("GET /api/me", srv.handleMe)

	log.Printf("11-kayan-oidc backend listening on :8080 (issuer=%s)", issuer)
	if err := http.ListenAndServe(":8080", corsMiddleware(mux)); err != nil {
		log.Fatal(err)
	}
}
