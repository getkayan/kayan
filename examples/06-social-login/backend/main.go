// Example 06: Social Login via GitHub OAuth2 (strategy: oauth2_github)
//
// Demonstrates authorization-code flow with state (CSRF) protection.
// In production set GITHUB_CLIENT_ID and GITHUB_CLIENT_SECRET env vars.
//
// Flow:
//  1. GET  /api/oauth/github/start             → redirect to GitHub
//  2. GET  /api/oauth/github/callback?code=&state= → exchange code, issue session
//  3. GET  /api/me                              Authorization: Bearer
package main

import (
	"crypto/rand"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"
	"sync"
	"time"
)

// ---- config ----

var (
	githubClientID     = envOr("GITHUB_CLIENT_ID", "YOUR_CLIENT_ID")
	githubClientSecret = envOr("GITHUB_CLIENT_SECRET", "YOUR_CLIENT_SECRET")
	redirectURI        = "http://localhost:5173/callback"
)

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

// ---- storage ----

type stateRecord struct {
	createdAt time.Time
}

type session struct {
	login string
	email string
}

var (
	mu       sync.Mutex
	states   = map[string]*stateRecord{}
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
	if len(auth) > 7 && auth[:7] == "Bearer " {
		return auth[7:]
	}
	return ""
}

// ---- handlers ----

// handleStart generates a random state, stores it, and returns the GitHub OAuth URL.
func handleStart(w http.ResponseWriter, r *http.Request) {
	state := randomHex(16)
	mu.Lock()
	states[state] = &stateRecord{createdAt: time.Now()}
	mu.Unlock()

	authURL := "https://github.com/login/oauth/authorize?" + url.Values{
		"client_id":    {githubClientID},
		"redirect_uri": {redirectURI},
		"scope":        {"read:user user:email"},
		"state":        {state},
	}.Encode()

	jsonResponse(w, http.StatusOK, map[string]string{"redirect_url": authURL})
}

// handleCallback validates state, exchanges the code for a GitHub token,
// fetches the GitHub user, and issues a Kayan session token.
func handleCallback(w http.ResponseWriter, r *http.Request) {
	state := r.URL.Query().Get("state")
	code := r.URL.Query().Get("code")

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

	// Exchange code for GitHub access token.
	ghToken, err := exchangeGitHubCode(code)
	if err != nil {
		log.Printf("GitHub token exchange error: %v", err)
		jsonResponse(w, http.StatusBadGateway, map[string]string{"error": "token exchange failed"})
		return
	}

	// Fetch GitHub user info.
	user, err := fetchGitHubUser(ghToken)
	if err != nil {
		log.Printf("GitHub user fetch error: %v", err)
		jsonResponse(w, http.StatusBadGateway, map[string]string{"error": "failed to fetch user"})
		return
	}

	token := "sess_" + randomHex(16)
	mu.Lock()
	sessions[token] = &session{login: user["login"].(string), email: fmt.Sprintf("%v", user["email"])}
	mu.Unlock()

	jsonResponse(w, http.StatusOK, map[string]string{"session_token": token})
}

func exchangeGitHubCode(code string) (string, error) {
	resp, err := http.PostForm("https://github.com/login/oauth/access_token", url.Values{
		"client_id":     {githubClientID},
		"client_secret": {githubClientSecret},
		"code":          {code},
	})
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	var result map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", err
	}
	if errMsg, ok := result["error"]; ok {
		return "", fmt.Errorf("github: %v", errMsg)
	}
	if token, ok := result["access_token"].(string); ok {
		return token, nil
	}
	return "", fmt.Errorf("no access_token in response")
}

func fetchGitHubUser(token string) (map[string]any, error) {
	req, _ := http.NewRequest("GET", "https://api.github.com/user", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/vnd.github+json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var user map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&user); err != nil {
		return nil, err
	}
	return user, nil
}

func handleMe(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	token := bearerToken(r)
	mu.Lock()
	sess, ok := sessions[token]
	mu.Unlock()
	if !ok {
		jsonResponse(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
		return
	}
	jsonResponse(w, http.StatusOK, map[string]string{"login": sess.login, "email": sess.email})
}

func main() {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/oauth/github/start", handleStart)
	mux.HandleFunc("/api/oauth/github/callback", handleCallback)
	mux.HandleFunc("/api/me", handleMe)

	log.Println("Social login (GitHub) example backend listening on :8080")
	log.Printf("GitHub Client ID: %s", githubClientID)
	log.Fatal(http.ListenAndServe(":8080", cors(mux)))
}
