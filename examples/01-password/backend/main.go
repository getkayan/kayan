// 01-password: Password authentication example backed by Kayan.
//
// Demonstrates:
//   - flow.PasswordAuth() to wire registration + login in one call
//   - An in-memory IdentityStorage implementation (drop in kgorm for production)
//   - session.NewHS256Strategy() for JWT session management
//   - POST /api/register, POST /api/login, GET /api/me, DELETE /api/logout
package main

import (
	"encoding/json"
	"fmt"
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
	"time"
)

// ---------- In-memory IdentityStorage ----------
// Replace this with gormstore.New(db) in production.

// ---------- Server ----------

type server struct {
	reg        *flow.RegistrationManager
	login      *flow.LoginManager
	sessions   *session.JWTStrategy
	revocation *session.MemoryRevocationStore
	repo       *kayantesting.MemoryStore
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

// POST /api/register – { email, password } → { id, email }
func (s *server) handleRegister(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.Email == "" || body.Password == "" {
		writeError(w, http.StatusBadRequest, "email and password required")
		return
	}

	// flow.RegistrationManager handles hashing, duplicate detection, and storage.
	identRaw, err := s.reg.Submit(r.Context(), "password",
		identity.JSON(fmt.Sprintf(`{"email":%q}`, body.Email)),
		body.Password,
	)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	ident := identRaw.(*identity.Identity)
	writeJSON(w, http.StatusCreated, map[string]string{
		"id":    ident.ID,
		"email": body.Email,
	})
}

// POST /api/login – { email, password } → { token }
func (s *server) handleLogin(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var body struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.Email == "" || body.Password == "" {
		writeError(w, http.StatusBadRequest, "email and password required")
		return
	}

	// flow.LoginManager delegates to the password strategy (bcrypt, constant-time).
	identRaw, err := s.login.Authenticate(r.Context(), "password", body.Email, body.Password)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "invalid credentials")
		return
	}

	ident := identRaw.(*identity.Identity)

	// Issue a JWT session via Kayan's session package.
	sess, err := s.sessions.Create(ctx, uuid.New().String(), ident.ID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not create session")
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{"token": sess.ID})
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

// DELETE /api/logout – Authorization: Bearer <token>
func (s *server) handleLogout(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	token := bearerToken(r)
	if token == "" {
		writeError(w, http.StatusUnauthorized, "missing token")
		return
	}
	sess, err := s.sessions.Validate(ctx, token)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "invalid session")
		return
	}
	_ = s.revocation.Revoke(r.Context(), sess.ID, sess.ExpiresAt)
	writeJSON(w, http.StatusOK, map[string]string{"message": "logged out"})
}

// ---------- Main ----------

func main() {
	repo := kayantesting.NewMemoryStore()

	// flow.PasswordAuth wires up RegistrationManager + LoginManager with bcrypt in one call.
	reg, login := flow.PasswordAuth(repo, func() any { return &identity.Identity{} }, "email")

	// JWT sessions — change the secret via environment variable in production.
	revocationStore := session.NewMemoryRevocationStore()
	jwtStrategy := session.NewHS256Strategy(sessionSecret(), 24*time.Hour)
	jwtStrategy.WithRevocationStore(revocationStore)

	srv := &server{reg: reg, login: login, sessions: jwtStrategy, revocation: revocationStore, repo: repo}

	mux := http.NewServeMux()
	mux.HandleFunc("POST /api/register", srv.handleRegister)
	mux.HandleFunc("POST /api/login", srv.handleLogin)
	mux.HandleFunc("GET /api/me", srv.handleMe)
	mux.HandleFunc("DELETE /api/logout", srv.handleLogout)

	log.Println("01-password backend listening on :8080")
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
