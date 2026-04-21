// 07-api-key: Machine-to-machine authentication via API keys backed by Kayan.
//
// Demonstrates:
//   - flow.NewAPIKeyStrategy() with flow.APIKeyRepository
//   - flow.GenerateAPIKey() for cryptographically random key generation
//   - flow.HashAPIKey() stores only the SHA-256 hash — raw key is shown once
//   - JWT session for human login; API key for M2M resource access
//
// Endpoints:
//   - POST   /api/register         – { email, password } → { id }
//   - POST   /api/login            – { email, password } → { session_token }
//   - POST   /api/keys/generate    – Authorization: Bearer → { api_key, key_id }
//   - DELETE /api/keys/{key_id}    – Authorization: Bearer → revoke key
//   - GET    /api/resource         – X-API-Key: <key> → protected resource
//   - GET    /api/me               – Authorization: Bearer <session_token>
package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"reflect"
	"strings"
	"sync"
	"time"

	"github.com/getkayan/kayan/core/flow"
	"github.com/getkayan/kayan/core/identity"
	"github.com/getkayan/kayan/core/session"
	"github.com/google/uuid"
)

// ---------- In-memory IdentityStorage + APIKeyRepository ----------

type apiKeyRecord struct {
	id         string // public key ID (prefix of raw key)
	keyHash    string // hex-encoded SHA-256; never the raw key
	identityID string
}

type memRepo struct {
	mu         sync.RWMutex
	identities map[string]any
	creds      map[string]*identity.Credential // identifier:type → Credential
	apiKeys    map[string]*apiKeyRecord        // keyHash → record
	keysByID   map[string]*apiKeyRecord        // keyID → record
}

func newMemRepo() *memRepo {
	return &memRepo{
		identities: make(map[string]any),
		creds:      make(map[string]*identity.Credential),
		apiKeys:    make(map[string]*apiKeyRecord),
		keysByID:   make(map[string]*apiKeyRecord),
	}
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

// flow.APIKeyRepository implementation

// FindIdentityByAPIKeyHash looks up the identity whose key matches the SHA-256 hash.
func (r *memRepo) FindIdentityByAPIKeyHash(_ context.Context, keyHash string, factory func() any) (any, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	rec, ok := r.apiKeys[keyHash]
	if !ok {
		return nil, errors.New("api key not found")
	}
	ident, ok := r.identities[rec.identityID]
	if !ok {
		return nil, errors.New("identity not found")
	}
	return ident, nil
}

// StoreAPIKey saves a new API key record (only the hash is persisted).
func (r *memRepo) StoreAPIKey(keyID, keyHash, identityID string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	rec := &apiKeyRecord{id: keyID, keyHash: keyHash, identityID: identityID}
	r.apiKeys[keyHash] = rec
	r.keysByID[keyID] = rec
}

// DeleteAPIKeyByID revokes an API key by its public ID.
func (r *memRepo) DeleteAPIKeyByID(keyID, identityID string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	rec, ok := r.keysByID[keyID]
	if !ok || rec.identityID != identityID {
		return errors.New("key not found or not owned by this identity")
	}
	delete(r.apiKeys, rec.keyHash)
	delete(r.keysByID, keyID)
	return nil
}

// ---------- Server ----------

type server struct {
	repo     *memRepo
	reg      *flow.RegistrationManager
	pwLogin  *flow.LoginManager
	apiLogin *flow.LoginManager
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
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization, X-API-Key")
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

// POST /api/register – { email, password }
func (s *server) handleRegister(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.Email == "" || body.Password == "" {
		writeError(w, http.StatusBadRequest, "email and password required")
		return
	}
	identRaw, err := s.reg.Submit(r.Context(), "password",
		identity.JSON(fmt.Sprintf(`{"email":%q}`, body.Email)),
		body.Password,
	)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	ident := identRaw.(*identity.Identity)
	writeJSON(w, http.StatusCreated, map[string]string{"id": ident.ID})
}

// POST /api/login – { email, password } → { session_token }
func (s *server) handleLogin(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.Email == "" || body.Password == "" {
		writeError(w, http.StatusBadRequest, "email and password required")
		return
	}
	identRaw, err := s.pwLogin.Authenticate(r.Context(), "password", body.Email, body.Password)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "invalid credentials")
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

// POST /api/keys/generate – Authorization: Bearer <session_token>
// Returns the raw API key once (never stored). Store only the key_id.
func (s *server) handleGenerateKey(w http.ResponseWriter, r *http.Request) {
	sess, err := s.sessions.Validate(bearerToken(r))
	if err != nil {
		writeError(w, http.StatusUnauthorized, "invalid session")
		return
	}

	// flow.GenerateAPIKey returns the raw key + its SHA-256 hash.
	rawKey, keyHash, err := flow.GenerateAPIKey(32)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "key generation failed")
		return
	}

	// The key ID is the first 8 hex characters (public, safe to expose).
	keyID := rawKey[:8]
	s.repo.StoreAPIKey(keyID, keyHash, sess.IdentityID)

	writeJSON(w, http.StatusCreated, map[string]string{
		"api_key": rawKey,
		"key_id":  keyID,
	})
}

// DELETE /api/keys/{key_id} – Authorization: Bearer
func (s *server) handleRevokeKey(w http.ResponseWriter, r *http.Request) {
	sess, err := s.sessions.Validate(bearerToken(r))
	if err != nil {
		writeError(w, http.StatusUnauthorized, "invalid session")
		return
	}
	keyID := strings.TrimPrefix(r.URL.Path, "/api/keys/")
	if keyID == "" {
		writeError(w, http.StatusBadRequest, "key_id required in path")
		return
	}
	if err := s.repo.DeleteAPIKeyByID(keyID, sess.IdentityID); err != nil {
		writeError(w, http.StatusNotFound, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"revoked": true})
}

// GET /api/resource – X-API-Key: <raw_key>
// Authenticated via APIKeyStrategy (SHA-256 lookup, constant-time comparison).
func (s *server) handleResource(w http.ResponseWriter, r *http.Request) {
	rawKey := r.Header.Get("X-API-Key")
	if rawKey == "" {
		writeError(w, http.StatusUnauthorized, "X-API-Key header required")
		return
	}
	// APIKeyStrategy.Authenticate: hashes the key and looks up the identity.
	identRaw, err := s.apiLogin.Authenticate(r.Context(), "api_key", "", rawKey)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "invalid API key")
		return
	}
	ident := identRaw.(*identity.Identity)
	writeJSON(w, http.StatusOK, map[string]string{
		"message":     "hello from protected resource",
		"identity_id": ident.ID,
	})
}

// GET /api/me – Authorization: Bearer
func (s *server) handleMe(w http.ResponseWriter, r *http.Request) {
	sess, err := s.sessions.Validate(bearerToken(r))
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
	writeJSON(w, http.StatusOK, map[string]string{"id": ident.ID, "email": email})
}

// ---------- Main ----------

func main() {
	repo := newMemRepo()
	factory := func() any { return &identity.Identity{} }

	// Password auth for human login.
	reg, pwLogin := flow.PasswordAuth(repo, factory, "email")

	// APIKeyStrategy for M2M resource access.
	// repo implements both domain.IdentityStorage and flow.APIKeyRepository.
	apiKeyStrategy := flow.NewAPIKeyStrategy(repo, factory)
	apiLogin := flow.NewLoginManager(repo, factory)
	apiLogin.RegisterStrategy(apiKeyStrategy)

	jwtStrategy := session.NewHS256Strategy("change-me-in-production", 24*time.Hour)

	srv := &server{
		repo:     repo,
		reg:      reg,
		pwLogin:  pwLogin,
		apiLogin: apiLogin,
		sessions: jwtStrategy,
	}

	mux := http.NewServeMux()
	mux.HandleFunc("POST /api/register", srv.handleRegister)
	mux.HandleFunc("POST /api/login", srv.handleLogin)
	mux.HandleFunc("POST /api/keys/generate", srv.handleGenerateKey)
	mux.HandleFunc("DELETE /api/keys/", srv.handleRevokeKey)
	mux.HandleFunc("GET /api/resource", srv.handleResource)
	mux.HandleFunc("GET /api/me", srv.handleMe)

	log.Println("07-api-key backend listening on :8080")
	if err := http.ListenAndServe(":8080", corsMiddleware(mux)); err != nil {
		log.Fatal(err)
	}
}
