// Example 10: LDAP Authentication (strategy: ldap)
//
// Simulates LDAP bind-based authentication without a real LDAP server.
// Pre-populated users: alice/alice123, bob/bob456.
//
// In production:
//   - Use github.com/go-ldap/ldap/v3
//   - Always use TLS (ldaps://) — never plain LDAP
//   - Two-step bind: service account search, then user re-bind
//   - Set LDAP_ADDR, LDAP_BASE_DN, LDAP_SERVICE_DN, LDAP_SERVICE_PASS env vars
//
// Flow:
//  1. POST /api/ldap/login  { username, password } → session_token
//  2. GET  /api/me          Authorization: Bearer
package main

import (
	"crypto/rand"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
	"sync"
)

// ---- simulated LDAP directory ----

type ldapUser struct {
	DN          string
	Username    string
	Password    string // In production: verified server-side by real LDAP bind
	DisplayName string
	Email       string
}

var directory = []*ldapUser{
	{DN: "uid=alice,ou=users,dc=example,dc=com", Username: "alice", Password: "alice123", DisplayName: "Alice Smith", Email: "alice@example.com"},
	{DN: "uid=bob,ou=users,dc=example,dc=com", Username: "bob", Password: "bob456", DisplayName: "Bob Jones", Email: "bob@example.com"},
}

// bindUser simulates a two-step LDAP bind:
// Step 1: service account searches for user DN by username attribute
// Step 2: re-bind as user with provided password
func bindUser(username, password string) (*ldapUser, error) {
	// Step 1: Search (service account bind omitted in simulation)
	var found *ldapUser
	for _, u := range directory {
		if u.Username == username {
			found = u
			break
		}
	}
	if found == nil {
		return nil, fmt.Errorf("user not found")
	}
	// Step 2: re-bind as user (check password)
	if found.Password != password {
		return nil, fmt.Errorf("invalid credentials")
	}
	return found, nil
}

// ---- storage ----

type session struct {
	username    string
	displayName string
	email       string
}

var (
	mu       sync.RWMutex
	sessions = map[string]*session{}
)

// ---- helpers ----

func randomHex(n int) string {
	b := make([]byte, n)
	rand.Read(b)
	return fmt.Sprintf("%x", b)
}

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

func bearerToken(r *http.Request) string {
	auth := r.Header.Get("Authorization")
	if strings.HasPrefix(auth, "Bearer ") {
		return auth[7:]
	}
	return ""
}

// ---- handlers ----

func handleLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var body struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.Username == "" || body.Password == "" {
		jsonResponse(w, http.StatusBadRequest, map[string]string{"error": "username and password required"})
		return
	}

	user, err := bindUser(body.Username, body.Password)
	if err != nil {
		log.Printf("[LDAP] Login failed for %q: %v", body.Username, err)
		jsonResponse(w, http.StatusUnauthorized, map[string]string{"error": "invalid credentials"})
		return
	}

	token := "sess_" + randomHex(16)
	mu.Lock()
	sessions[token] = &session{
		username:    user.Username,
		displayName: user.DisplayName,
		email:       user.Email,
	}
	mu.Unlock()

	log.Printf("[LDAP] Login success for %q (%s)", user.Username, user.DN)
	jsonResponse(w, http.StatusOK, map[string]string{"session_token": token})
}

func handleMe(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	token := bearerToken(r)
	mu.RLock()
	sess, ok := sessions[token]
	mu.RUnlock()
	if !ok {
		jsonResponse(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
		return
	}
	jsonResponse(w, http.StatusOK, map[string]string{
		"username":     sess.username,
		"display_name": sess.displayName,
		"email":        sess.email,
	})
}

func main() {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/ldap/login", handleLogin)
	mux.HandleFunc("/api/me", handleMe)

	log.Println("LDAP example backend listening on :8080")
	log.Println("Pre-populated users: alice/alice123, bob/bob456")
	log.Println("In production: use github.com/go-ldap/ldap/v3 with TLS")
	log.Fatal(http.ListenAndServe(":8080", cors(mux)))
}
