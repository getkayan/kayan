// Example 07: API Key Authentication (strategy: api_key)
//
// Demonstrates machine-to-machine authentication via long-lived API keys.
// Keys are SHA-256 hashed before storage — the raw key is shown only once at generation time.
//
// Endpoints:
//
//	POST   /api/keys/generate   { name }        → { id, name, key }  ← raw key shown once
//	GET    /api/keys            Authorization   → list of key records (no raw keys)
//	DELETE /api/keys/{id}       Authorization   → revoke key
//	GET    /api/resource        Authorization   → protected resource (demonstrates M2M auth)
package main

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"
)

// ---- storage ----

type apiKey struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	Hash      string    `json:"-"` // never exposed
	CreatedAt time.Time `json:"created_at"`
}

var (
	mu       sync.RWMutex
	keyStore = map[string]*apiKey{} // hash → key record
	keysByID = map[string]*apiKey{} // id → key record
)

// ---- helpers ----

func cors(next http.Handler) http.Handler {
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

func jsonResponse(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

func hashAPIKey(raw string) string {
	h := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(h[:])
}

func generateAPIKey() (raw, id string, err error) {
	b := make([]byte, 32)
	if _, err = rand.Read(b); err != nil {
		return
	}
	raw = "kayan_" + hex.EncodeToString(b)
	idBytes := make([]byte, 8)
	rand.Read(idBytes)
	id = hex.EncodeToString(idBytes)
	return
}

func bearerToken(r *http.Request) string {
	auth := r.Header.Get("Authorization")
	if strings.HasPrefix(auth, "Bearer ") {
		return auth[7:]
	}
	return ""
}

func lookupByKey(raw string) *apiKey {
	hash := hashAPIKey(raw)
	mu.RLock()
	defer mu.RUnlock()
	return keyStore[hash]
}

// ---- handlers ----

func handleGenerate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var body struct {
		Name string `json:"name"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.Name == "" {
		jsonResponse(w, http.StatusBadRequest, map[string]string{"error": "name required"})
		return
	}

	raw, id, err := generateAPIKey()
	if err != nil {
		jsonResponse(w, http.StatusInternalServerError, map[string]string{"error": "key generation failed"})
		return
	}

	rec := &apiKey{
		ID:        id,
		Name:      body.Name,
		Hash:      hashAPIKey(raw),
		CreatedAt: time.Now().UTC(),
	}

	mu.Lock()
	keyStore[rec.Hash] = rec
	keysByID[id] = rec
	mu.Unlock()

	log.Printf("[API Key] Generated key %q for %q", id, body.Name)

	// Return raw key once — never stored, never loggable again.
	jsonResponse(w, http.StatusCreated, map[string]any{
		"id":   id,
		"name": body.Name,
		"key":  raw, // shown ONCE
	})
}

func handleListKeys(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	// Require a valid API key to list keys (demonstrates key-based auth).
	token := bearerToken(r)
	if token == "" || lookupByKey(token) == nil {
		jsonResponse(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
		return
	}
	mu.RLock()
	keys := make([]map[string]any, 0, len(keysByID))
	for _, k := range keysByID {
		keys = append(keys, map[string]any{"id": k.ID, "name": k.Name, "created_at": k.CreatedAt})
	}
	mu.RUnlock()
	jsonResponse(w, http.StatusOK, keys)
}

func handleDeleteKey(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodDelete {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	token := bearerToken(r)
	if token == "" || lookupByKey(token) == nil {
		jsonResponse(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
		return
	}
	// Extract ID from path: DELETE /api/keys/<id>
	id := strings.TrimPrefix(r.URL.Path, "/api/keys/")
	if id == "" {
		jsonResponse(w, http.StatusBadRequest, map[string]string{"error": "id required"})
		return
	}
	mu.Lock()
	rec, ok := keysByID[id]
	if ok {
		delete(keyStore, rec.Hash)
		delete(keysByID, id)
	}
	mu.Unlock()
	if !ok {
		jsonResponse(w, http.StatusNotFound, map[string]string{"error": "key not found"})
		return
	}
	jsonResponse(w, http.StatusOK, map[string]string{"message": fmt.Sprintf("key %s revoked", id)})
}

func handleResource(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	token := bearerToken(r)
	rec := lookupByKey(token)
	if rec == nil {
		jsonResponse(w, http.StatusUnauthorized, map[string]string{"error": "invalid API key"})
		return
	}
	jsonResponse(w, http.StatusOK, map[string]any{
		"message":  "You accessed a protected resource!",
		"key_name": rec.Name,
		"key_id":   rec.ID,
	})
}

func main() {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/keys/generate", handleGenerate)
	mux.HandleFunc("/api/keys/", func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Path
		if path == "/api/keys/" || path == "/api/keys" {
			handleListKeys(w, r)
		} else {
			handleDeleteKey(w, r)
		}
	})
	mux.HandleFunc("/api/resource", handleResource)

	log.Println("API key example backend listening on :8080")
	log.Fatal(http.ListenAndServe(":8080", cors(mux)))
}
