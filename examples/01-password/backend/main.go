// 01-password: Password authentication example using bcrypt.
// Demonstrates: register, login, and protected endpoint with Bearer token.
package main

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
	"sync"

	"golang.org/x/crypto/bcrypt"
)

// ---------- In-memory storage ----------

type User struct {
	ID           string
	Email        string
	PasswordHash []byte
}

type Session struct {
	Token  string
	UserID string
}

var (
	mu       sync.RWMutex
	users    = map[string]*User{}    // email → User
	sessions = map[string]*Session{} // token → Session
)

// ---------- Helpers ----------

func newID() string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func newToken() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return "sess_" + hex.EncodeToString(b)
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

// corsMiddleware adds CORS headers and handles pre-flight OPTIONS requests.
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

// bearerToken extracts the token from "Authorization: Bearer <token>".
func bearerToken(r *http.Request) string {
	parts := strings.SplitN(r.Header.Get("Authorization"), " ", 2)
	if len(parts) == 2 && parts[0] == "Bearer" {
		return parts[1]
	}
	return ""
}

// ---------- Handlers ----------

// POST /api/register – { email, password } → hash with bcrypt cost 12, store, return { id, email }
func handleRegister(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.Email == "" || body.Password == "" {
		writeError(w, http.StatusBadRequest, "email and password required")
		return
	}

	mu.Lock()
	defer mu.Unlock()

	if _, exists := users[body.Email]; exists {
		writeError(w, http.StatusConflict, "email already registered")
		return
	}

	// Hash the password with bcrypt cost 12.
	hash, err := bcrypt.GenerateFromPassword([]byte(body.Password), 12)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to hash password")
		return
	}

	u := &User{ID: newID(), Email: body.Email, PasswordHash: hash}
	users[body.Email] = u

	writeJSON(w, http.StatusCreated, map[string]string{"id": u.ID, "email": u.Email})
}

// POST /api/login – { email, password } → bcrypt compare, return { token }
func handleLogin(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.Email == "" || body.Password == "" {
		writeError(w, http.StatusBadRequest, "email and password required")
		return
	}

	mu.RLock()
	u, ok := users[body.Email]
	mu.RUnlock()

	if !ok {
		// Use bcrypt dummy work to prevent timing attacks.
		_ = bcrypt.CompareHashAndPassword([]byte("$2a$12$dummy"), []byte(body.Password))
		writeError(w, http.StatusUnauthorized, "invalid credentials")
		return
	}

	// Compare password — bcrypt.CompareHashAndPassword is constant-time.
	if err := bcrypt.CompareHashAndPassword(u.PasswordHash, []byte(body.Password)); err != nil {
		writeError(w, http.StatusUnauthorized, "invalid credentials")
		return
	}

	token := newToken()

	mu.Lock()
	sessions[token] = &Session{Token: token, UserID: u.ID}
	mu.Unlock()

	writeJSON(w, http.StatusOK, map[string]string{"token": token})
}

// GET /api/me – Authorization: Bearer <token> → return { id, email }
func handleMe(w http.ResponseWriter, r *http.Request) {
	token := bearerToken(r)
	if token == "" {
		writeError(w, http.StatusUnauthorized, "missing token")
		return
	}

	mu.RLock()
	sess, ok := sessions[token]
	mu.RUnlock()

	if !ok {
		writeError(w, http.StatusUnauthorized, "invalid session")
		return
	}

	// Find user by ID.
	mu.RLock()
	var found *User
	for _, u := range users {
		if u.ID == sess.UserID {
			found = u
			break
		}
	}
	mu.RUnlock()

	if found == nil {
		writeError(w, http.StatusUnauthorized, "user not found")
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{"id": found.ID, "email": found.Email})
}

// ---------- Main ----------

func main() {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /api/register", handleRegister)
	mux.HandleFunc("POST /api/login", handleLogin)
	mux.HandleFunc("GET /api/me", handleMe)

	handler := corsMiddleware(mux)

	fmt.Println("01-password backend listening on :8080")
	if err := http.ListenAndServe(":8080", handler); err != nil {
		log.Fatal(err)
	}
}
