package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/getkayan/kayan/core/config"
	"github.com/getkayan/kayan/core/flow"
	"github.com/getkayan/kayan/core/identity"
	"github.com/google/uuid"
	"os"
)

var (
	regMgr   *flow.RegistrationManager
	loginMgr *flow.LoginManager
	oidcMgr  *flow.OIDCManager
	storage  *InMemStorage
)

func main() {
	storage = NewInMemStorage()
	factory := func() any { return &identity.Identity{} }

	// 1. Setup Kayan Managers
	regMgr = flow.NewRegistrationManager(storage, factory)
	loginMgr = flow.NewLoginManager(storage)

	// 2. Setup Linker for Account Unification
	linker := flow.NewDefaultLinker(storage, factory)
	regMgr.SetLinker(linker)
	regMgr.PreventPasswordCapture = true

	// 3. Register Password Strategy
	hasher := flow.NewBcryptHasher(10)
	pwStrategy := flow.NewPasswordStrategy(storage, hasher, "email", factory)
	regMgr.RegisterStrategy(pwStrategy)
	loginMgr.RegisterStrategy(pwStrategy)

	// 4. Setup OIDC Manager for Google
	googleConfig := config.OIDCProvider{
		Issuer:       "https://accounts.google.com",
		ClientID:     os.Getenv("GOOGLE_CLIENT_ID"),
		ClientSecret: os.Getenv("GOOGLE_CLIENT_SECRET"),
		RedirectURL:  "http://localhost:4000/api/auth/google/callback",
	}
	oidcMgr, _ = flow.NewOIDCManager(storage, map[string]config.OIDCProvider{"google": googleConfig}, factory)
	oidcMgr.SetLinker(linker)
	oidcMgr.SetIDGenerator(func() any { return uuid.New().String() })

	// 5. Setup Routes
	mux := http.NewServeMux()
	mux.HandleFunc("/api/auth/register", handleRegister)
	mux.HandleFunc("/api/auth/login", handleLogin)
	mux.HandleFunc("/api/auth/google/login", handleGoogleLogin)
	mux.HandleFunc("/api/auth/google/callback", handleGoogleCallback)
	mux.HandleFunc("/api/auth/me", handleMe)

	// Simple CORS
	handler := corsMiddleware(mux)

	fmt.Println("Kayan Demo Backend running on :4000")
	log.Fatal(http.ListenAndServe(":4000", handler))
}

func handleRegister(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	traits := identity.JSON(fmt.Sprintf(`{"email": "%s", "email_verified": true}`, req.Email))
	ident, err := regMgr.Submit(r.Context(), "password", traits, req.Password)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	respondJSON(w, ident)
}

func handleLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	ident, err := loginMgr.Authenticate(r.Context(), "password", req.Email, req.Password)
	if err != nil {
		http.Error(w, "Invalid credentials", http.StatusUnauthorized)
		return
	}

	// Issue a mock session cookie
	issueSession(w, ident)
	respondJSON(w, ident)
}

func handleGoogleLogin(w http.ResponseWriter, r *http.Request) {
	if oidcMgr == nil {
		http.Error(w, "OIDC not configured", http.StatusInternalServerError)
		return
	}
	state := "demo-state-" + uuid.New().String()
	url, err := oidcMgr.GetAuthURL("google", state)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, url, http.StatusFound)
}

func handleGoogleCallback(w http.ResponseWriter, r *http.Request) {
	code := r.URL.Query().Get("code")
	if code == "" {
		http.Error(w, "Missing code", http.StatusBadRequest)
		return
	}

	ident, err := oidcMgr.HandleCallback(r.Context(), "google", code)
	if err != nil {
		http.Error(w, "OIDC login failed: "+err.Error(), http.StatusInternalServerError)
		return
	}

	issueSession(w, ident)
	http.Redirect(w, r, "http://localhost:3000/dashboard", http.StatusFound)
}

func handleMe(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie("kayan_session")
	if err != nil {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	id := strings.TrimPrefix(cookie.Value, "sess_")
	ident, err := storage.GetIdentity(nil, id)
	if err != nil {
		http.Error(w, "Session invalid", http.StatusUnauthorized)
		return
	}

	respondJSON(w, ident)
}

func issueSession(w http.ResponseWriter, ident any) {
	fi := ident.(*identity.Identity)
	http.SetCookie(w, &http.Cookie{
		Name:     "kayan_session",
		Value:    "sess_" + fmt.Sprintf("%v", fi.ID),
		Path:     "/",
		HttpOnly: true,
		Expires:  time.Now().Add(24 * time.Hour),
	})
}

func respondJSON(w http.ResponseWriter, data any) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(data)
}

func corsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "http://localhost:3000")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
		w.Header().Set("Access-Control-Allow-Credentials", "true")

		if r.Method == http.MethodOptions {
			return
		}
		next.ServeHTTP(w, r)
	})
}
