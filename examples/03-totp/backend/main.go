// 03-totp: Password + TOTP two-factor authentication backed by Kayan.
//
// Demonstrates:
//   - flow.PasswordAuth() for password registration + login
//   - flow.NewTOTPStrategy() for TOTP verification (RFC 6238)
//   - Two-step login: password → partial JWT → TOTP → full JWT
//   - POST /api/register, POST /api/login/password, POST /api/totp/enroll
//   - POST /api/totp/verify, GET /api/me
package main

import (
	"context"
	"crypto/rand"
	"encoding/base32"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/getkayan/kayan/core/flow"
	"github.com/getkayan/kayan/core/identity"
	"github.com/getkayan/kayan/core/session"
	kayantesting "github.com/getkayan/kayan/kayan-testing"
	"github.com/google/uuid"
	"log"
	"net/http"
	"os"
	"reflect"
	"strings"
	"sync"
	"time"
)

// ---------- In-memory IdentityStorage + TOTPRepository ----------

type totpRecord struct {
	secret       string // base32-encoded TOTP secret
	usedCounters map[uint64]bool
}

type memRepo struct {
	// The storage contract comes from the shared in-memory store, which is
	// verified by kayantesting.StorageSuite. Only the strategy-specific
	// methods below are written here.
	*kayantesting.MemoryStore

	mu         sync.RWMutex
	identities map[string]any
	creds      map[string]*identity.Credential
	totpData   map[string]*totpRecord // identityID → TOTP data
}

func newMemRepo() *memRepo {
	return &memRepo{
		MemoryStore: kayantesting.NewMemoryStore(),
		identities:  make(map[string]any),
		creds:       make(map[string]*identity.Credential),
		totpData:    make(map[string]*totpRecord),
	}
}

// IdentityStorage methods

// TOTPRepository methods

func (r *memRepo) FindIdentityByField(ctx context.Context, field, value string, factory func() any) (any, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	for _, ident := range r.identities {
		v := reflect.ValueOf(ident)
		if v.Kind() == reflect.Ptr {
			v = v.Elem()
		}
		f := v.FieldByName(field)
		if f.IsValid() && fmt.Sprintf("%v", f.Interface()) == value {
			return ident, nil
		}
	}
	// Also search by JSON traits
	for _, ident := range r.identities {
		if ts, ok := ident.(flow.TraitSource); ok {
			var m map[string]any
			if json.Unmarshal(ts.GetTraits(), &m) == nil {
				if fmt.Sprintf("%v", m[field]) == value {
					return ident, nil
				}
			}
		}
	}
	return nil, errors.New("identity not found")
}

func (r *memRepo) FindTOTPSecret(ctx context.Context, identityID any) (string, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	rec, ok := r.totpData[fmt.Sprintf("%v", identityID)]
	if !ok || rec.secret == "" {
		return "", errors.New("totp secret not found")
	}
	return rec.secret, nil
}

func (r *memRepo) MarkTOTPUsed(ctx context.Context, identityID any, counter uint64) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	id := fmt.Sprintf("%v", identityID)
	rec, ok := r.totpData[id]
	if !ok {
		return errors.New("totp record not found")
	}
	if rec.usedCounters[counter] {
		return errors.New("totp: replay detected")
	}
	rec.usedCounters[counter] = true
	return nil
}

// SetTOTPSecret stores a TOTP secret for an identity (called during enrollment).
func (r *memRepo) SetTOTPSecret(identityID, secret string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.totpData[identityID] = &totpRecord{
		secret:       secret,
		usedCounters: make(map[uint64]bool),
	}
}

// ---------- Server ----------

type server struct {
	repo        *memRepo
	reg         *flow.RegistrationManager
	pwLogin     *flow.LoginManager
	totpLogin   *flow.LoginManager
	partialSess *session.JWTStrategy // short-lived: password done, TOTP pending
	fullSess    *session.JWTStrategy // long-lived: fully authenticated
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

// POST /api/login/password – { email, password } → { partial_token, totp_enrolled }
// Issues a short-lived partial JWT; TOTP step still required.
func (s *server) handleLoginPassword(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var body struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.Email == "" || body.Password == "" {
		writeError(w, http.StatusBadRequest, "email and password required")
		return
	}

	// Password strategy handles bcrypt comparison (constant-time).
	identRaw, err := s.pwLogin.Authenticate(r.Context(), "password", body.Email, body.Password)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "invalid credentials")
		return
	}
	ident := identRaw.(*identity.Identity)

	// Issue a short-lived partial JWT (5 min) — TOTP step pending.
	partialSess, err := s.partialSess.Create(ctx, uuid.New().String(), ident.ID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "session error")
		return
	}

	_, totpErr := s.repo.FindTOTPSecret(r.Context(), ident.ID)
	writeJSON(w, http.StatusOK, map[string]any{
		"partial_token": partialSess.ID,
		"totp_enrolled": totpErr == nil,
	})
}

// POST /api/totp/enroll – Authorization: Bearer <partial_token> → { secret, otpauth_uri }
func (s *server) handleTOTPEnroll(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	token := bearerToken(r)
	partialSess, err := s.partialSess.Validate(ctx, token)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "valid partial token required")
		return
	}

	identRaw, err := s.repo.GetIdentity(ctx, func() any { return &identity.Identity{} }, partialSess.IdentityID)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "identity not found")
		return
	}
	ident := identRaw.(*identity.Identity)

	// Generate a cryptographically random 20-byte TOTP secret.
	raw := make([]byte, 20)
	if _, err := rand.Read(raw); err != nil {
		writeError(w, http.StatusInternalServerError, "failed to generate secret")
		return
	}
	secret := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(raw)

	s.repo.SetTOTPSecret(ident.ID, secret)

	var email string
	var m map[string]any
	if json.Unmarshal(ident.Traits, &m) == nil {
		email, _ = m["email"].(string)
	}

	otpauthURI := fmt.Sprintf("otpauth://totp/Kayan%%20Example%%3A%s?secret=%s&issuer=KayanExample",
		email, secret)

	writeJSON(w, http.StatusOK, map[string]string{
		"secret":      secret,
		"otpauth_uri": otpauthURI,
	})
}

// POST /api/totp/verify – Authorization: Bearer <partial_token>, { code } → { session_token }
func (s *server) handleTOTPVerify(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	token := bearerToken(r)
	partialSess, err := s.partialSess.Validate(ctx, token)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "valid partial token required")
		return
	}

	var body struct {
		Code string `json:"code"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.Code == "" {
		writeError(w, http.StatusBadRequest, "code required")
		return
	}

	identRaw, err := s.repo.GetIdentity(ctx, func() any { return &identity.Identity{} }, partialSess.IdentityID)
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

	// TOTPStrategy.Authenticate handles RFC 6238 verification + replay protection.
	_, err = s.totpLogin.Authenticate(r.Context(), "totp", email, body.Code)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "invalid TOTP code")
		return
	}

	// Upgrade to a full long-lived JWT, and destroy the partial one.
	//
	// The partial token proves only that the password step passed. Leaving it
	// alive after the upgrade means anyone holding it can replay this endpoint
	// for the rest of its lifetime, so the second factor gates nothing.
	if err := s.partialSess.Delete(ctx, token); err != nil {
		writeError(w, http.StatusInternalServerError, "session error")
		return
	}

	fullSess, err := s.fullSess.Create(ctx, uuid.New().String(), ident.ID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "session error")
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"session_token": fullSess.ID})
}

// GET /api/me – Authorization: Bearer <session_token>
func (s *server) handleMe(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	token := bearerToken(r)
	sess, err := s.fullSess.Validate(ctx, token)
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
	repo := newMemRepo()
	factory := func() any { return &identity.Identity{} }

	// Password: registration + first-factor login
	reg, pwLogin := flow.PasswordAuth(repo, factory, "email")

	// TOTP: second-factor login (uses same repo which also implements TOTPRepository)
	totpStrategy := flow.NewTOTPStrategy(repo, factory, "email")
	totpLogin := flow.NewLoginManager(repo, factory)
	totpLogin.RegisterStrategy(totpStrategy)

	// Two JWT tiers: partial (5 min) and full (24 h).
	//
	// The partial tier carries a revocation store because its token has to be
	// destroyed the moment the second factor succeeds. Without one, Delete has
	// nowhere to record the revocation and the pre-MFA token stays valid for
	// its full five minutes -- replayable against the verify endpoint.
	partialSess := session.NewHS256Strategy(sessionSecret(), 5*time.Minute).
		WithRevocationStore(session.NewMemoryRevocationStore())
	fullSess := session.NewHS256Strategy(sessionSecret(), 24*time.Hour)

	srv := &server{
		repo:        repo,
		reg:         reg,
		pwLogin:     pwLogin,
		totpLogin:   totpLogin,
		partialSess: partialSess,
		fullSess:    fullSess,
	}

	mux := http.NewServeMux()
	mux.HandleFunc("POST /api/register", srv.handleRegister)
	mux.HandleFunc("POST /api/login/password", srv.handleLoginPassword)
	mux.HandleFunc("POST /api/totp/enroll", srv.handleTOTPEnroll)
	mux.HandleFunc("POST /api/totp/verify", srv.handleTOTPVerify)
	mux.HandleFunc("GET /api/me", srv.handleMe)

	log.Println("03-totp backend listening on :8080")
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
