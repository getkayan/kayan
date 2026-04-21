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
	"log"
	"net/http"
	"reflect"
	"strings"
	"sync"
	"time"

	"github.com/getkayan/kayan/core/domain"
	"github.com/getkayan/kayan/core/flow"
	"github.com/getkayan/kayan/core/identity"
	"github.com/getkayan/kayan/core/session"
	"github.com/google/uuid"
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

// ensureIdentity auto-creates an identity + "otp" credential for the email address
// if one does not already exist.
func (r *memRepo) ensureIdentity(email string) {
	if _, err := r.GetCredentialByIdentifier(email, "otp"); err == nil {
		return
	}
	id := uuid.New().String()
	ident := &identity.Identity{
		ID:     id,
		Traits: identity.JSON(fmt.Sprintf(`{"email":%q}`, email)),
	}
	_ = r.CreateIdentity(ident)
	cred := &identity.Credential{
		IdentityID: id,
		Type:       "otp",
		Identifier: email,
	}
	_ = r.CreateCredential(cred)
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
	tokenStore := newMemTokenStore()
	factory := func() any { return &identity.Identity{} }

	// OTPStrategy: generate codes, store in tokenStore, deliver via stdoutEmailSender.
	otpStrategy := flow.NewOTPStrategy(repo, tokenStore, &stdoutEmailSender{})

	login := flow.NewLoginManager(repo, factory)
	login.RegisterStrategy(otpStrategy)

	jwtStrategy := session.NewHS256Strategy("change-me-in-production", 24*time.Hour)

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
