// Example 05: SMS OTP (strategy: sms_otp)
//
// Demonstrates multi-step passwordless authentication via a 6-digit OTP
// sent to the user's phone number (printed to stdout here instead of SMS).
//
// Flow:
//  1. POST /api/sms/initiate  { phone } → generate 6-digit code, log it, store 5 min TTL
//  2. POST /api/sms/verify    { phone, code } → verify, issue session token
//  3. GET  /api/me            Authorization: Bearer <token>
package main

import (
	"crypto/rand"
	"encoding/json"
	"fmt"
	"log"
	"math/big"
	"net/http"
	"sync"
	"time"
)

// ---- storage ----

type otpRecord struct {
	code    string
	phone   string
	expires time.Time
}

type session struct {
	phone string
}

var (
	mu       sync.Mutex
	otpStore = map[string]*otpRecord{} // phone → otp
	sessions = map[string]*session{}   // token → session
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

func randomToken(n int) string {
	b := make([]byte, n)
	rand.Read(b)
	return fmt.Sprintf("%x", b)
}

func generate6DigitCode() string {
	n, _ := rand.Int(rand.Reader, big.NewInt(1_000_000))
	return fmt.Sprintf("%06d", n.Int64())
}

func bearerToken(r *http.Request) string {
	auth := r.Header.Get("Authorization")
	if len(auth) > 7 && auth[:7] == "Bearer " {
		return auth[7:]
	}
	return ""
}

// ---- handlers ----

func handleInitiate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var body struct {
		Phone string `json:"phone"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.Phone == "" {
		jsonResponse(w, http.StatusBadRequest, map[string]string{"error": "phone required"})
		return
	}

	code := generate6DigitCode()

	mu.Lock()
	otpStore[body.Phone] = &otpRecord{
		code:    code,
		phone:   body.Phone,
		expires: time.Now().Add(5 * time.Minute),
	}
	mu.Unlock()

	// In production: send via Twilio / SNS. Here we just log.
	log.Printf("[SMS OTP] Phone: %s  Code: %s", body.Phone, code)

	jsonResponse(w, http.StatusOK, map[string]string{"message": "OTP sent (see server logs)"})
}

func handleVerify(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var body struct {
		Phone string `json:"phone"`
		Code  string `json:"code"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		jsonResponse(w, http.StatusBadRequest, map[string]string{"error": "invalid body"})
		return
	}

	mu.Lock()
	rec, ok := otpStore[body.Phone]
	mu.Unlock()

	if !ok || time.Now().After(rec.expires) {
		jsonResponse(w, http.StatusUnauthorized, map[string]string{"error": "OTP expired or not found"})
		return
	}
	if rec.code != body.Code {
		jsonResponse(w, http.StatusUnauthorized, map[string]string{"error": "invalid code"})
		return
	}

	// Consume the OTP (single-use)
	mu.Lock()
	delete(otpStore, body.Phone)
	token := "sess_" + randomToken(16)
	sessions[token] = &session{phone: body.Phone}
	mu.Unlock()

	jsonResponse(w, http.StatusOK, map[string]string{"session_token": token})
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
	jsonResponse(w, http.StatusOK, map[string]string{"phone": sess.phone})
}

func main() {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/sms/initiate", handleInitiate)
	mux.HandleFunc("/api/sms/verify", handleVerify)
	mux.HandleFunc("/api/me", handleMe)

	log.Println("SMS OTP example backend listening on :8080")
	log.Fatal(http.ListenAndServe(":8080", cors(mux)))
}
