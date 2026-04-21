// 08-recovery-codes: MFA recovery via one-time recovery codes backed by Kayan.
//
// Demonstrates:
//   - flow.NewRecoveryCodeStrategy() with flow.RecoveryCodeRepository
//   - flow.GenerateRecoveryCodes() for cryptographically random code generation
//   - flow.NewBcryptHasher() for code hashing (only hashes stored, never plaintext)
//   - Normal password login + recovery fallback (each code is single-use)
//
// Endpoints:
//   - POST /api/register                – { email, password } → { id }
//   - POST /api/login                   – { email, password } → { session_token }
//   - POST /api/recovery-codes/generate – Authorization: Bearer → { codes: [...] }
//   - POST /api/login/recover           – { email, code } → { session_token }
//   - GET  /api/me                      – Authorization: Bearer <session_token>
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

// ---------- In-memory IdentityStorage + RecoveryCodeRepository ----------

type memRepo struct {
	mu            sync.RWMutex
	identities    map[string]any
	creds         map[string]*identity.Credential
	recoveryCodes map[string][]*flow.RecoveryCodeRecord // identityID → codes
}

func newMemRepo() *memRepo {
	return &memRepo{
		identities:    make(map[string]any),
		creds:         make(map[string]*identity.Credential),
		recoveryCodes: make(map[string][]*flow.RecoveryCodeRecord),
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

// flow.RecoveryCodeRepository implementation

// FindIdentityByField looks up an identity by a named field and value.
// Used by RecoveryCodeStrategy to find the identity by email.
func (r *memRepo) FindIdentityByField(_ context.Context, field, value string, factory func() any) (any, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	for _, ident := range r.identities {
		// Check JSON traits.
		if ts, ok := ident.(flow.TraitSource); ok {
			var m map[string]any
			if json.Unmarshal(ts.GetTraits(), &m) == nil {
				if fmt.Sprintf("%v", m[strings.ToLower(field)]) == value {
					return ident, nil
				}
			}
		}
		// Check struct fields.
		v := reflect.ValueOf(ident)
		if v.Kind() == reflect.Ptr {
			v = v.Elem()
		}
		f := v.FieldByName(field)
		if f.IsValid() && fmt.Sprintf("%v", f.Interface()) == value {
			return ident, nil
		}
	}
	return nil, errors.New("identity not found")
}

// FindUnusedRecoveryCode returns the first unused recovery code for an identity.
func (r *memRepo) FindUnusedRecoveryCode(_ context.Context, identityID any) (*flow.RecoveryCodeRecord, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	id := fmt.Sprintf("%v", identityID)
	for _, rec := range r.recoveryCodes[id] {
		if rec != nil {
			return rec, nil
		}
	}
	return nil, flow.ErrNoRecoveryCodesRemaining
}

// MarkRecoveryCodeUsed removes the code so it cannot be used again.
func (r *memRepo) MarkRecoveryCodeUsed(_ context.Context, identityID any, codeID string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	id := fmt.Sprintf("%v", identityID)
	codes := r.recoveryCodes[id]
	for i, rec := range codes {
		if rec != nil && rec.ID == codeID {
			codes[i] = nil // mark used (single-use)
			return nil
		}
	}
	return errors.New("code not found")
}

// StoreRecoveryCodes saves hashed recovery codes for an identity (replaces existing).
func (r *memRepo) StoreRecoveryCodes(identityID string, hashes []string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	records := make([]*flow.RecoveryCodeRecord, len(hashes))
	for i, h := range hashes {
		records[i] = &flow.RecoveryCodeRecord{
			ID:   uuid.New().String(),
			Hash: h,
		}
	}
	r.recoveryCodes[identityID] = records
}

// ---------- Server ----------

type server struct {
	repo         *memRepo
	reg          *flow.RegistrationManager
	pwLogin      *flow.LoginManager
	recoverLogin *flow.LoginManager
	sessions     *session.JWTStrategy
	hasher       *flow.BcryptHasher
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
	writeJSON(w, http.StatusCreated, map[string]string{"id": ident.ID, "email": body.Email})
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

// POST /api/recovery-codes/generate – Authorization: Bearer
// Generates 10 fresh recovery codes. Each code is shown once; only bcrypt hashes stored.
func (s *server) handleGenerateCodes(w http.ResponseWriter, r *http.Request) {
	sess, err := s.sessions.Validate(bearerToken(r))
	if err != nil {
		writeError(w, http.StatusUnauthorized, "invalid session")
		return
	}

	// flow.GenerateRecoveryCodes: cryptographically random codes + their bcrypt hashes.
	plaintexts, hashes, err := flow.GenerateRecoveryCodes(s.hasher, 10)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to generate codes")
		return
	}
	s.repo.StoreRecoveryCodes(sess.IdentityID, hashes)

	writeJSON(w, http.StatusCreated, map[string]any{"codes": plaintexts})
}

// POST /api/login/recover – { email, code } → { session_token }
// RecoveryCodeStrategy verifies the code via bcrypt; marks it used on success.
func (s *server) handleRecover(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Email string `json:"email"`
		Code  string `json:"code"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.Email == "" || body.Code == "" {
		writeError(w, http.StatusBadRequest, "email and code required")
		return
	}

	identRaw, err := s.recoverLogin.Authenticate(r.Context(), "recovery_code", body.Email, body.Code)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "invalid or already-used recovery code")
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
	hasher := flow.NewBcryptHasher(12)

	// Password auth.
	reg, pwLogin := flow.PasswordAuth(repo, factory, "email")

	// Recovery-code strategy: looks up identity by "email" field, uses bcrypt for code comparison.
	recoveryStrategy := flow.NewRecoveryCodeStrategy(repo, hasher, factory, "email")
	recoverLogin := flow.NewLoginManager(repo, factory)
	recoverLogin.RegisterStrategy(recoveryStrategy)

	jwtStrategy := session.NewHS256Strategy("change-me-in-production", 24*time.Hour)

	srv := &server{
		repo:         repo,
		reg:          reg,
		pwLogin:      pwLogin,
		recoverLogin: recoverLogin,
		sessions:     jwtStrategy,
		hasher:       hasher,
	}

	mux := http.NewServeMux()
	mux.HandleFunc("POST /api/register", srv.handleRegister)
	mux.HandleFunc("POST /api/login", srv.handleLogin)
	mux.HandleFunc("POST /api/recovery-codes/generate", srv.handleGenerateCodes)
	mux.HandleFunc("POST /api/login/recover", srv.handleRecover)
	mux.HandleFunc("GET /api/me", srv.handleMe)

	log.Println("08-recovery-codes backend listening on :8080")
	if err := http.ListenAndServe(":8080", corsMiddleware(mux)); err != nil {
		log.Fatal(err)
	}
}
