// 04-webauthn: Simulated WebAuthn / Passkey flow (FIDO2).
// NOTE: This is a simplified simulation to illustrate the API shape.
// In production use github.com/go-webauthn/webauthn with real cryptographic verification.
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
)

// ---------- Storage ----------

type User struct {
	ID          string
	Email       string
	Credentials []MockCredential
}

// MockCredential simulates a stored public-key credential.
// In production this would hold the COSE public key + sign count.
type MockCredential struct {
	ID string `json:"id"`
}

type Challenge struct {
	Value string
	Email string
}

type Session struct {
	Token  string
	UserID string
}

var (
	mu         sync.RWMutex
	users      = map[string]*User{}
	challenges = map[string]*Challenge{} // challenge → email (pending)
	sessions   = map[string]*Session{}
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

// POST /api/webauthn/register/begin – { email } → { challenge, rpId, user }
func handleRegisterBegin(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Email string `json:"email"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.Email == "" {
		writeError(w, http.StatusBadRequest, "email required")
		return
	}

	challenge := randomHex(32) // In production: cryptographically random, stored server-side

	mu.Lock()
	if _, ok := users[body.Email]; !ok {
		users[body.Email] = &User{ID: randomHex(8), Email: body.Email}
	}
	challenges[challenge] = &Challenge{Value: challenge, Email: body.Email}
	mu.Unlock()

	writeJSON(w, http.StatusOK, map[string]any{
		"challenge": challenge,
		"rpId":      "localhost", // Relying Party identifier — must match the origin in production
		"user": map[string]string{
			"id":          users[body.Email].ID,
			"name":        body.Email,
			"displayName": body.Email,
		},
	})
}

// POST /api/webauthn/register/finish – { email, credential } → { ok }
// In production: verify attestation object, validate signature, store public key.
func handleRegisterFinish(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Email      string `json:"email"`
		Credential struct {
			ID string `json:"id"`
		} `json:"credential"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.Email == "" || body.Credential.ID == "" {
		writeError(w, http.StatusBadRequest, "email and credential.id required")
		return
	}

	mu.Lock()
	defer mu.Unlock()

	u, ok := users[body.Email]
	if !ok {
		writeError(w, http.StatusNotFound, "user not found — call register/begin first")
		return
	}

	// Store the mock credential (production: verify attestation + store public key).
	u.Credentials = append(u.Credentials, MockCredential{ID: body.Credential.ID})

	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

// POST /api/webauthn/login/begin – { email } → { challenge, allowCredentials }
func handleLoginBegin(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Email string `json:"email"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.Email == "" {
		writeError(w, http.StatusBadRequest, "email required")
		return
	}

	mu.RLock()
	u, ok := users[body.Email]
	mu.RUnlock()

	if !ok || len(u.Credentials) == 0 {
		writeError(w, http.StatusNotFound, "no passkey registered for this email")
		return
	}

	challenge := randomHex(32)

	mu.Lock()
	challenges[challenge] = &Challenge{Value: challenge, Email: body.Email}
	mu.Unlock()

	// Build allowCredentials list from stored credential IDs.
	creds := make([]map[string]string, len(u.Credentials))
	for i, c := range u.Credentials {
		creds[i] = map[string]string{"type": "public-key", "id": c.ID}
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"challenge":        challenge,
		"rpId":             "localhost",
		"allowCredentials": creds,
	})
}

// POST /api/webauthn/login/finish – { email, assertion } → { session_token }
// In production: verify authenticatorData, clientDataJSON, signature against stored public key.
func handleLoginFinish(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Email     string `json:"email"`
		Assertion struct {
			ID string `json:"id"`
		} `json:"assertion"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.Email == "" {
		writeError(w, http.StatusBadRequest, "email and assertion required")
		return
	}

	mu.Lock()
	defer mu.Unlock()

	u, ok := users[body.Email]
	if !ok {
		writeError(w, http.StatusUnauthorized, "user not found")
		return
	}

	// Simulate verification: check that the credential ID is stored for this user.
	found := false
	for _, c := range u.Credentials {
		if c.ID == body.Assertion.ID {
			found = true
			break
		}
	}
	if !found {
		writeError(w, http.StatusUnauthorized, "credential not recognised")
		return
	}

	// Issue session.
	sessToken := "sess_" + randomHex(16)
	sessions[sessToken] = &Session{Token: sessToken, UserID: u.ID}

	writeJSON(w, http.StatusOK, map[string]string{"session_token": sessToken})
}

// GET /api/me
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

	writeJSON(w, http.StatusOK, map[string]any{"id": found.ID, "email": found.Email})
}

// ---------- Main ----------

func main() {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /api/webauthn/register/begin", handleRegisterBegin)
	mux.HandleFunc("POST /api/webauthn/register/finish", handleRegisterFinish)
	mux.HandleFunc("POST /api/webauthn/login/begin", handleLoginBegin)
	mux.HandleFunc("POST /api/webauthn/login/finish", handleLoginFinish)
	mux.HandleFunc("GET /api/me", handleMe)

	fmt.Println("04-webauthn backend listening on :8080")
	fmt.Println("NOTE: This is a simulated flow. In production use github.com/go-webauthn/webauthn")
	if err := http.ListenAndServe(":8080", corsMiddleware(mux)); err != nil {
		log.Fatal(err)
	}
}
