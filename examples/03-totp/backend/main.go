// 03-totp: Password + TOTP two-factor authentication.
// TOTP is implemented inline (HMAC-SHA1, 30s step, 6 digits) with no external lib.
// Demonstrates: partial token after password, TOTP enrollment, TOTP verification.
package main

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"encoding/base32"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"log"
	"math"
	"net/http"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/bcrypt"
)

// ---------- In-memory storage ----------

type User struct {
	ID           string
	Email        string
	PasswordHash []byte
	TOTPSecret   string // base32-encoded; empty = not enrolled
	TOTPEnrolled bool
}

type Session struct {
	Token     string
	UserID    string
	IsPartial bool // partial = password done, TOTP pending
}

var (
	mu       sync.RWMutex
	users    = map[string]*User{}
	sessions = map[string]*Session{}
)

// ---------- TOTP (RFC 6238 / RFC 4226) — no external library ----------

// totpGenSecret generates a random 20-byte base32 secret.
func totpGenSecret() string {
	b := make([]byte, 20)
	_, _ = rand.Read(b)
	return base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(b)
}

// totpCounter returns the current 30-second time step counter.
func totpCounter() uint64 {
	return uint64(time.Now().Unix() / 30)
}

// totpCode computes a 6-digit TOTP code for a given base32 secret and counter.
func totpCode(secret string, counter uint64) (string, error) {
	key, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(strings.ToUpper(secret))
	if err != nil {
		return "", err
	}

	// HMAC-SHA1 of the 8-byte big-endian counter.
	msg := make([]byte, 8)
	binary.BigEndian.PutUint64(msg, counter)
	mac := hmac.New(sha1.New, key)
	mac.Write(msg)
	h := mac.Sum(nil)

	// Dynamic truncation (RFC 4226 §5.4).
	offset := h[len(h)-1] & 0x0f
	code := binary.BigEndian.Uint32(h[offset:offset+4]) & 0x7fffffff
	otp := int(code) % int(math.Pow10(6))

	return fmt.Sprintf("%06d", otp), nil
}

// totpVerify checks the code against current counter ±1 window.
func totpVerify(secret, code string) bool {
	c := totpCounter()
	for _, delta := range []uint64{0, 1, c - 1} { // current, next, previous
		got, err := totpCode(secret, c-delta)
		if err != nil {
			continue
		}
		if hmac.Equal([]byte(got), []byte(code)) {
			return true
		}
	}
	return false
}

// ---------- Helpers ----------

func randomHex(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	s := make([]byte, n*2)
	const hx = "0123456789abcdef"
	for i, v := range b {
		s[i*2] = hx[v>>4]
		s[i*2+1] = hx[v&0xf]
	}
	return string(s)
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

// sessionByToken returns the session for a given token (nil if not found).
func sessionByToken(token string) *Session {
	mu.RLock()
	defer mu.RUnlock()
	return sessions[token]
}

func userByID(id string) *User {
	mu.RLock()
	defer mu.RUnlock()
	for _, u := range users {
		if u.ID == id {
			return u
		}
	}
	return nil
}

// ---------- Handlers ----------

// POST /api/register – { email, password }
func handleRegister(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.Email == "" || body.Password == "" {
		writeError(w, http.StatusBadRequest, "email and password required")
		return
	}

	mu.Lock()
	defer mu.Unlock()

	if _, exists := users[body.Email]; exists {
		writeError(w, http.StatusConflict, "email already registered")
		return
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(body.Password), 12)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to hash password")
		return
	}

	u := &User{ID: randomHex(8), Email: body.Email, PasswordHash: hash}
	users[body.Email] = u

	writeJSON(w, http.StatusCreated, map[string]string{"id": u.ID, "email": u.Email})
}

// POST /api/login/password – { email, password } → { partial_token, totp_required }
func handleLoginPassword(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.Email == "" || body.Password == "" {
		writeError(w, http.StatusBadRequest, "email and password required")
		return
	}

	mu.RLock()
	u, ok := users[body.Email]
	mu.RUnlock()

	if !ok {
		_ = bcrypt.CompareHashAndPassword([]byte("$2a$12$dummy"), []byte(body.Password))
		writeError(w, http.StatusUnauthorized, "invalid credentials")
		return
	}

	if err := bcrypt.CompareHashAndPassword(u.PasswordHash, []byte(body.Password)); err != nil {
		writeError(w, http.StatusUnauthorized, "invalid credentials")
		return
	}

	// Issue a partial token — TOTP still required.
	partial := "partial_" + randomHex(16)

	mu.Lock()
	sessions[partial] = &Session{Token: partial, UserID: u.ID, IsPartial: true}
	mu.Unlock()

	writeJSON(w, http.StatusOK, map[string]any{
		"partial_token": partial,
		"totp_required": true,
		"totp_enrolled": u.TOTPEnrolled,
	})
}

// POST /api/totp/enroll – Authorization: partial_token → { secret, otpauth_uri }
func handleTOTPEnroll(w http.ResponseWriter, r *http.Request) {
	token := bearerToken(r)
	sess := sessionByToken(token)
	if sess == nil || !sess.IsPartial {
		writeError(w, http.StatusUnauthorized, "valid partial token required")
		return
	}

	u := userByID(sess.UserID)
	if u == nil {
		writeError(w, http.StatusInternalServerError, "user not found")
		return
	}

	// Generate a fresh TOTP secret.
	secret := totpGenSecret()

	mu.Lock()
	u.TOTPSecret = secret
	mu.Unlock()

	// Build an otpauth:// URI for QR code scanners.
	uri := fmt.Sprintf("otpauth://totp/KayanDemo:%s?secret=%s&issuer=KayanDemo&algorithm=SHA1&digits=6&period=30",
		u.Email, secret)

	writeJSON(w, http.StatusOK, map[string]string{
		"secret":      secret,
		"otpauth_uri": uri,
	})
}

// POST /api/totp/confirm – Authorization: partial_token, { code } → mark enrolled
func handleTOTPConfirm(w http.ResponseWriter, r *http.Request) {
	token := bearerToken(r)
	sess := sessionByToken(token)
	if sess == nil || !sess.IsPartial {
		writeError(w, http.StatusUnauthorized, "valid partial token required")
		return
	}

	var body struct {
		Code string `json:"code"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.Code == "" {
		writeError(w, http.StatusBadRequest, "code required")
		return
	}

	u := userByID(sess.UserID)
	if u == nil || u.TOTPSecret == "" {
		writeError(w, http.StatusBadRequest, "totp not initiated — call /api/totp/enroll first")
		return
	}

	if !totpVerify(u.TOTPSecret, body.Code) {
		writeError(w, http.StatusUnauthorized, "invalid TOTP code")
		return
	}

	mu.Lock()
	u.TOTPEnrolled = true
	mu.Unlock()

	writeJSON(w, http.StatusOK, map[string]string{"message": "TOTP enrolled successfully"})
}

// POST /api/login/totp – Authorization: partial_token, { code } → { session_token }
func handleLoginTOTP(w http.ResponseWriter, r *http.Request) {
	token := bearerToken(r)
	sess := sessionByToken(token)
	if sess == nil || !sess.IsPartial {
		writeError(w, http.StatusUnauthorized, "valid partial token required")
		return
	}

	var body struct {
		Code string `json:"code"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.Code == "" {
		writeError(w, http.StatusBadRequest, "code required")
		return
	}

	u := userByID(sess.UserID)
	if u == nil || !u.TOTPEnrolled {
		writeError(w, http.StatusBadRequest, "totp not enrolled")
		return
	}

	if !totpVerify(u.TOTPSecret, body.Code) {
		writeError(w, http.StatusUnauthorized, "invalid TOTP code")
		return
	}

	// Upgrade partial token to full session.
	sessToken := "sess_" + randomHex(16)

	mu.Lock()
	delete(sessions, token) // invalidate partial
	sessions[sessToken] = &Session{Token: sessToken, UserID: u.ID, IsPartial: false}
	mu.Unlock()

	writeJSON(w, http.StatusOK, map[string]string{"session_token": sessToken})
}

// GET /api/me – Authorization: Bearer <full session token>
func handleMe(w http.ResponseWriter, r *http.Request) {
	token := bearerToken(r)
	if token == "" {
		writeError(w, http.StatusUnauthorized, "missing token")
		return
	}

	sess := sessionByToken(token)
	if sess == nil || sess.IsPartial {
		writeError(w, http.StatusUnauthorized, "invalid or incomplete session")
		return
	}

	u := userByID(sess.UserID)
	if u == nil {
		writeError(w, http.StatusUnauthorized, "user not found")
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"id":            u.ID,
		"email":         u.Email,
		"totp_enrolled": u.TOTPEnrolled,
	})
}

// ---------- Main ----------

func main() {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /api/register", handleRegister)
	mux.HandleFunc("POST /api/login/password", handleLoginPassword)
	mux.HandleFunc("POST /api/totp/enroll", handleTOTPEnroll)
	mux.HandleFunc("POST /api/totp/confirm", handleTOTPConfirm)
	mux.HandleFunc("POST /api/login/totp", handleLoginTOTP)
	mux.HandleFunc("GET /api/me", handleMe)

	fmt.Println("03-totp backend listening on :8080")
	if err := http.ListenAndServe(":8080", corsMiddleware(mux)); err != nil {
		log.Fatal(err)
	}
}
