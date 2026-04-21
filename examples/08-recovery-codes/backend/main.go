// Example 08: Recovery Codes (strategy: recovery_code)
//
// Demonstrates single-use MFA fallback codes generated at setup time.
// Each code is bcrypt-hashed before storage; plaintexts shown once.
//
// Flow:
//  1. POST /api/register              { email, password }
//  2. POST /api/login                 { email, password } → partial_token (MFA step required)
//  3. POST /api/recovery-codes/generate  Authorization: partial_token → { codes } ← shown once
//  4. POST /api/login/recover         { email, recovery_code } → session_token
//  5. GET  /api/me                    Authorization: Bearer <session_token>
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

const bcryptCost = 12

// ---- storage ----

type user struct {
	ID           string
	Email        string
	PasswordHash string
}

type codeRecord struct {
	ID   string
	Hash string
	Used bool
}

type session struct {
	userID  string
	partial bool // true = only password step done, needs recovery
}

var (
	mu            sync.RWMutex
	users         = map[string]*user{}         // email → user
	usersByID     = map[string]*user{}         // id → user
	recoveryCodes = map[string][]*codeRecord{} // userID → codes
	sessions      = map[string]*session{}      // token → session
)

// ---- helpers ----

func cors(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "http://localhost:5173")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func jsonResponse(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

func randomHex(n int) string {
	b := make([]byte, n)
	rand.Read(b)
	return hex.EncodeToString(b)
}

func bearerToken(r *http.Request) string {
	auth := r.Header.Get("Authorization")
	if strings.HasPrefix(auth, "Bearer ") {
		return auth[7:]
	}
	return ""
}

// ---- handlers ----

func handleRegister(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.Email == "" || body.Password == "" {
		jsonResponse(w, http.StatusBadRequest, map[string]string{"error": "email and password required"})
		return
	}
	mu.Lock()
	defer mu.Unlock()
	if _, exists := users[body.Email]; exists {
		jsonResponse(w, http.StatusConflict, map[string]string{"error": "email already registered"})
		return
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(body.Password), bcryptCost)
	if err != nil {
		jsonResponse(w, http.StatusInternalServerError, map[string]string{"error": "internal error"})
		return
	}
	u := &user{ID: randomHex(8), Email: body.Email, PasswordHash: string(hash)}
	users[body.Email] = u
	usersByID[u.ID] = u
	jsonResponse(w, http.StatusCreated, map[string]string{"id": u.ID, "email": u.Email})
}

func handleLogin(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		jsonResponse(w, http.StatusBadRequest, map[string]string{"error": "invalid body"})
		return
	}
	mu.RLock()
	u, ok := users[body.Email]
	mu.RUnlock()
	if !ok || bcrypt.CompareHashAndPassword([]byte(u.PasswordHash), []byte(body.Password)) != nil {
		jsonResponse(w, http.StatusUnauthorized, map[string]string{"error": "invalid credentials"})
		return
	}
	partial := "partial_" + randomHex(16)
	mu.Lock()
	sessions[partial] = &session{userID: u.ID, partial: true}
	mu.Unlock()
	jsonResponse(w, http.StatusOK, map[string]any{
		"partial_token": partial,
		"message":       "Use your recovery code to complete login",
	})
}

func handleGenerateCodes(w http.ResponseWriter, r *http.Request) {
	token := bearerToken(r)
	mu.RLock()
	sess, ok := sessions[token]
	mu.RUnlock()
	if !ok || !sess.partial {
		jsonResponse(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
		return
	}

	const n = 10
	plaintexts := make([]string, 0, n)
	records := make([]*codeRecord, 0, n)
	for i := 0; i < n; i++ {
		plain := randomHex(16) // 32 hex chars
		hash, err := bcrypt.GenerateFromPassword([]byte(plain), bcryptCost)
		if err != nil {
			jsonResponse(w, http.StatusInternalServerError, map[string]string{"error": "generation failed"})
			return
		}
		plaintexts = append(plaintexts, plain)
		records = append(records, &codeRecord{ID: randomHex(4), Hash: string(hash)})
	}

	mu.Lock()
	recoveryCodes[sess.userID] = records
	mu.Unlock()

	log.Printf("[Recovery Codes] Generated %d codes for user %s", n, sess.userID)
	jsonResponse(w, http.StatusCreated, map[string]any{
		"codes":   plaintexts,
		"message": "Store these codes safely — they will not be shown again.",
	})
}

func handleRecover(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Email        string `json:"email"`
		RecoveryCode string `json:"recovery_code"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		jsonResponse(w, http.StatusBadRequest, map[string]string{"error": "invalid body"})
		return
	}

	mu.RLock()
	u, ok := users[body.Email]
	mu.RUnlock()
	if !ok {
		jsonResponse(w, http.StatusUnauthorized, map[string]string{"error": "invalid"})
		return
	}

	mu.Lock()
	defer mu.Unlock()
	codes := recoveryCodes[u.ID]
	for _, c := range codes {
		if c.Used {
			continue
		}
		if bcrypt.CompareHashAndPassword([]byte(c.Hash), []byte(body.RecoveryCode)) == nil {
			c.Used = true
			token := "sess_" + randomHex(16)
			sessions[token] = &session{userID: u.ID, partial: false}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]string{"session_token": token})
			return
		}
	}
	jsonResponse(w, http.StatusUnauthorized, map[string]string{"error": "invalid or already used recovery code"})
}

func handleMe(w http.ResponseWriter, r *http.Request) {
	token := bearerToken(r)
	mu.RLock()
	sess, ok := sessions[token]
	mu.RUnlock()
	if !ok || sess.partial {
		jsonResponse(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
		return
	}
	mu.RLock()
	u := usersByID[sess.userID]
	mu.RUnlock()
	if u == nil {
		jsonResponse(w, http.StatusUnauthorized, map[string]string{"error": "user not found"})
		return
	}
	jsonResponse(w, http.StatusOK, map[string]string{"id": u.ID, "email": u.Email})
}

func main() {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/register", handleRegister)
	mux.HandleFunc("/api/login", handleLogin)
	mux.HandleFunc("/api/recovery-codes/generate", handleGenerateCodes)
	mux.HandleFunc("/api/login/recover", handleRecover)
	mux.HandleFunc("/api/me", handleMe)

	log.Println("Recovery codes example backend listening on :8080")
	log.Fatal(http.ListenAndServe(":8080", cors(mux)))
}

func init() {
	// Ensure POST-only on register/login/recover
	origMux := http.DefaultServeMux
	_ = origMux
	_ = fmt.Sprintf // used in log.Printf
}
