// Example 09: Email OTP (strategy: email_otp)
//
// Sends a 6-digit code to the user's email (logged to stdout in this demo).
//
// Flow:
//  1. POST /api/otp/send   { email } → generate 6-digit code, log to stdout, 10min TTL
//  2. POST /api/otp/verify { email, code } → verify, return session_token
//  3. GET  /api/me         Authorization: Bearer
package main

import (
	"crypto/rand"
	"encoding/json"
	"fmt"
	"log"
	"math/big"
	"net/http"
	"strings"
	"sync"
	"time"
)

type otpRecord struct {
	code    string
	expires time.Time
}

type session struct {
	email string
}

var (
	mu       sync.Mutex
	otpStore = map[string]*otpRecord{} // email → otp
	sessions = map[string]*session{}
)

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
	return fmt.Sprintf("%x", b)
}

func generate6Digit() string {
	n, _ := rand.Int(rand.Reader, big.NewInt(1_000_000))
	return fmt.Sprintf("%06d", n.Int64())
}

func bearerToken(r *http.Request) string {
	auth := r.Header.Get("Authorization")
	if strings.HasPrefix(auth, "Bearer ") {
		return auth[7:]
	}
	return ""
}

func handleSend(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var body struct {
		Email string `json:"email"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.Email == "" {
		jsonResponse(w, http.StatusBadRequest, map[string]string{"error": "email required"})
		return
	}

	code := generate6Digit()
	mu.Lock()
	otpStore[body.Email] = &otpRecord{code: code, expires: time.Now().Add(10 * time.Minute)}
	mu.Unlock()

	// In production send via SMTP / SendGrid etc.
	log.Printf("[Email OTP] To: %s  Code: %s", body.Email, code)
	jsonResponse(w, http.StatusOK, map[string]string{"message": "OTP sent (see server logs)"})
}

func handleVerify(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var body struct {
		Email string `json:"email"`
		Code  string `json:"code"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		jsonResponse(w, http.StatusBadRequest, map[string]string{"error": "invalid body"})
		return
	}

	mu.Lock()
	rec, ok := otpStore[body.Email]
	mu.Unlock()

	if !ok || time.Now().After(rec.expires) || rec.code != body.Code {
		jsonResponse(w, http.StatusUnauthorized, map[string]string{"error": "invalid or expired OTP"})
		return
	}

	mu.Lock()
	delete(otpStore, body.Email) // single-use
	token := "sess_" + randomHex(16)
	sessions[token] = &session{email: body.Email}
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
	jsonResponse(w, http.StatusOK, map[string]string{"email": sess.email})
}

func main() {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/otp/send", handleSend)
	mux.HandleFunc("/api/otp/verify", handleVerify)
	mux.HandleFunc("/api/me", handleMe)

	log.Println("Email OTP example backend listening on :8080")
	log.Fatal(http.ListenAndServe(":8080", cors(mux)))
}
