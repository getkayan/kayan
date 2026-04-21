// 02-magic-link: Passwordless magic-link authentication.
// Demonstrates: generating a signed token, simulating email delivery via stdout,
// verifying the token, and issuing a session.
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
	"time"
)

// ---------- In-memory storage ----------

type User struct {
	ID    string
	Email string
}

type MagicToken struct {
	Token   string
	Email   string
	Expires time.Time
}

type Session struct {
	Token  string
	UserID string
}

var (
	mu          sync.RWMutex
	users       = map[string]*User{}       // email → User
	magicTokens = map[string]*MagicToken{} // token → MagicToken
	sessions    = map[string]*Session{}    // session_token → Session
)

// ---------- Helpers ----------

func randomHex(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
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

// ---------- Handlers ----------

// POST /api/magic/initiate – { email } → generate 32-byte hex token, 15 min TTL, log to stdout.
func handleMagicInitiate(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Email string `json:"email"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.Email == "" {
		writeError(w, http.StatusBadRequest, "email required")
		return
	}

	// Ensure the user record exists (auto-create on first use).
	mu.Lock()
	if _, ok := users[body.Email]; !ok {
		users[body.Email] = &User{ID: randomHex(8), Email: body.Email}
	}

	// Generate a 32-byte hex token with a 15-minute TTL.
	token := randomHex(32)
	magicTokens[token] = &MagicToken{
		Token:   token,
		Email:   body.Email,
		Expires: time.Now().Add(15 * time.Minute),
	}
	mu.Unlock()

	// In production, send this link via your email provider.
	// Here we log it so the developer can copy/paste during development.
	log.Printf("[MAGIC LINK] To: %s | Link: http://localhost:5173/verify?token=%s\n", body.Email, token)

	writeJSON(w, http.StatusOK, map[string]string{"message": "check your email (token logged to stdout)"})
}

// GET /api/magic/verify?token=<t> – verify token, return { session_token }.
func handleMagicVerify(w http.ResponseWriter, r *http.Request) {
	token := r.URL.Query().Get("token")
	if token == "" {
		writeError(w, http.StatusBadRequest, "token required")
		return
	}

	mu.Lock()
	defer mu.Unlock()

	mt, ok := magicTokens[token]
	if !ok || time.Now().After(mt.Expires) {
		// Delete expired token.
		delete(magicTokens, token)
		writeError(w, http.StatusUnauthorized, "invalid or expired token")
		return
	}

	// Single-use: delete once verified.
	delete(magicTokens, token)

	u := users[mt.Email]
	if u == nil {
		writeError(w, http.StatusInternalServerError, "user not found")
		return
	}

	sessToken := "sess_" + randomHex(16)
	sessions[sessToken] = &Session{Token: sessToken, UserID: u.ID}

	writeJSON(w, http.StatusOK, map[string]string{"session_token": sessToken})
}

// GET /api/me – Authorization: Bearer <token> → return { id, email }.
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
	mux.HandleFunc("POST /api/magic/initiate", handleMagicInitiate)
	mux.HandleFunc("GET /api/magic/verify", handleMagicVerify)
	mux.HandleFunc("GET /api/me", handleMe)

	fmt.Println("02-magic-link backend listening on :8080")
	fmt.Println("Magic links are printed to stdout — check the console after initiating.")
	if err := http.ListenAndServe(":8080", corsMiddleware(mux)); err != nil {
		log.Fatal(err)
	}
}
