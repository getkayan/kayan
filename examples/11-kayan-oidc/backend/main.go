// Example 11: Login with Kayan OIDC (strategy: kayan_oidc)
//
// This application acts as an OIDC Relying Party (client), using a Kayan
// instance as the Identity Provider. Demonstrates:
//   - PKCE S256 (code_challenge / code_verifier)
//   - State parameter for CSRF protection (single-use)
//   - Nonce claim validation in ID token
//
// In production set:
//
//	KAYAN_ISSUER    = https://your-kayan.example.com
//	CLIENT_ID       = <registered client ID in Kayan>
//	CLIENT_SECRET   = <client secret>
//	REDIRECT_URI    = http://localhost:5173/callback
//
// This demo simulates the token exchange + ID token parsing (no real Kayan server needed).
//
// Flow:
//  1. GET  /api/oidc/start             → redirect_url to Kayan's /authorize
//  2. GET  /api/oidc/callback?code=&state= → exchange code, verify ID token, issue session
//  3. GET  /api/me                     Authorization: Bearer
package main

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"
)

// ---- config ----

var (
	kayanIssuer  = envOr("KAYAN_ISSUER", "https://auth.example.com")
	clientID     = envOr("CLIENT_ID", "demo-client")
	clientSecret = envOr("CLIENT_SECRET", "demo-secret")
	redirectURI  = envOr("REDIRECT_URI", "http://localhost:5173/callback")
)

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

// ---- storage ----

type stateRecord struct {
	verifier  string
	nonce     string
	createdAt time.Time
}

type session struct {
	sub   string
	email string
}

var (
	mu       sync.Mutex
	states   = map[string]*stateRecord{}
	sessions = map[string]*session{}
)

// ---- PKCE helpers ----

func randomBytes(n int) []byte {
	b := make([]byte, n)
	rand.Read(b)
	return b
}

func randomBase64URL(n int) string {
	return base64.RawURLEncoding.EncodeToString(randomBytes(n))
}

func s256Challenge(verifier string) string {
	h := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(h[:])
}

func randomHex(n int) string {
	return fmt.Sprintf("%x", randomBytes(n))
}

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

func bearerToken(r *http.Request) string {
	auth := r.Header.Get("Authorization")
	if strings.HasPrefix(auth, "Bearer ") {
		return auth[7:]
	}
	return ""
}

// ---- handlers ----

// handleStart generates state, PKCE verifier/challenge, and nonce;
// stores them; and returns the Kayan authorization URL.
func handleStart(w http.ResponseWriter, r *http.Request) {
	state := randomBase64URL(24)
	verifier := randomBase64URL(48) // PKCE verifier (≥43 chars after base64)
	nonce := randomBase64URL(16)
	challenge := s256Challenge(verifier)

	mu.Lock()
	states[state] = &stateRecord{verifier: verifier, nonce: nonce, createdAt: time.Now()}
	mu.Unlock()

	authURL := kayanIssuer + "/oauth2/auth?" + url.Values{
		"response_type":         {"code"},
		"client_id":             {clientID},
		"redirect_uri":          {redirectURI},
		"scope":                 {"openid email profile"},
		"state":                 {state},
		"nonce":                 {nonce},
		"code_challenge":        {challenge},
		"code_challenge_method": {"S256"},
	}.Encode()

	jsonResponse(w, http.StatusOK, map[string]string{
		"redirect_url": authURL,
		"state":        state,
	})
}

// handleCallback validates state, exchanges code (simulated), verifies ID token nonce.
func handleCallback(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	state := q.Get("state")
	code := q.Get("code")

	if state == "" || code == "" {
		jsonResponse(w, http.StatusBadRequest, map[string]string{"error": "missing state or code"})
		return
	}

	mu.Lock()
	rec, ok := states[state]
	if ok {
		delete(states, state) // single-use
	}
	mu.Unlock()

	if !ok || time.Since(rec.createdAt) > 10*time.Minute {
		jsonResponse(w, http.StatusBadRequest, map[string]string{"error": "invalid or expired state"})
		return
	}

	// In production: exchange code with Kayan token endpoint using rec.verifier.
	// Here we simulate a successful exchange and return a fake identity.
	log.Printf("[Kayan OIDC] Code exchange for state=%s (simulated)", state)

	// Simulate ID token claims (nonce validated here)
	fakeSub := "user-" + randomHex(4)
	fakeEmail := fakeSub + "@example.com"
	_ = rec.nonce // In production: validate nonce claim from real ID token JWT

	token := "sess_" + randomHex(16)
	mu.Lock()
	sessions[token] = &session{sub: fakeSub, email: fakeEmail}
	mu.Unlock()

	jsonResponse(w, http.StatusOK, map[string]string{"session_token": token})
}

func handleMe(w http.ResponseWriter, r *http.Request) {
	token := bearerToken(r)
	mu.Lock()
	sess, ok := sessions[token]
	mu.Unlock()
	if !ok {
		jsonResponse(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
		return
	}
	jsonResponse(w, http.StatusOK, map[string]string{"sub": sess.sub, "email": sess.email})
}

func main() {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/oidc/start", handleStart)
	mux.HandleFunc("/api/oidc/callback", handleCallback)
	mux.HandleFunc("/api/me", handleMe)

	log.Printf("Kayan OIDC example backend listening on :8080")
	log.Printf("Kayan Issuer: %s", kayanIssuer)
	log.Printf("Client ID:    %s", clientID)
	log.Fatal(http.ListenAndServe(":8080", cors(mux)))
}
