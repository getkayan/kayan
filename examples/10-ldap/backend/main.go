// 10-ldap: LDAP / Active Directory authentication backed by Kayan.
//
// Demonstrates:
//   - flow.NewLDAPStrategy() with custom flow.LDAPDialer + flow.LDAPConn
//   - In-memory simulated LDAP directory (alice/alice123, bob/bob456)
//   - flow.LDAPConfig with BaseDN, UsernameAttribute, TraitAttributes
//   - JWT session via session.NewHS256Strategy()
//
// The simulated LDAPDialer does not open a real network connection —
// it verifies bind credentials against an in-memory user map. In production,
// replace simulatedDialer with a real implementation backed by github.com/go-ldap/ldap/v3.
//
// Endpoints:
//   - POST /api/ldap/login – { username, password } → { session_token }
//   - GET  /api/me         – Authorization: Bearer <session_token>
package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/getkayan/kayan/core/flow"
	"github.com/getkayan/kayan/core/identity"
	"github.com/getkayan/kayan/core/session"
	// kayantesting.MemoryStore keeps everything in process memory and loses it
	// on restart. It is what lets this example run with no database; a real
	// deployment uses kayan-gorm or another persistent adapter.
	kayantesting "github.com/getkayan/kayan/kayan-testing"
	"github.com/google/uuid"
	"log"
	"net/http"
	"os"
	"strings"
	"time"
)

// ---------- Simulated LDAP directory (in-memory) ----------

// ldapUser represents a user in the simulated LDAP directory.
type ldapUser struct {
	DN         string
	Password   string
	Attributes map[string][]string
}

// simulatedDialer implements flow.LDAPDialer using an in-memory directory.
// In production, replace this with a real LDAP connection (github.com/go-ldap/ldap/v3).
type simulatedDialer struct {
	users []*ldapUser
}

func newSimulatedDialer() *simulatedDialer {
	return &simulatedDialer{
		users: []*ldapUser{
			{
				DN:       "uid=alice,ou=users,dc=example,dc=com",
				Password: "alice123",
				Attributes: map[string][]string{
					"uid":  {"alice"},
					"mail": {"alice@example.com"},
					"cn":   {"Alice Example"},
				},
			},
			{
				DN:       "uid=bob,ou=users,dc=example,dc=com",
				Password: "bob456",
				Attributes: map[string][]string{
					"uid":  {"bob"},
					"mail": {"bob@example.com"},
					"cn":   {"Bob Example"},
				},
			},
		},
	}
}

func (d *simulatedDialer) DialTLS(_ context.Context, _ string) (flow.LDAPConn, error) {
	return &simulatedConn{dialer: d}, nil
}

// simulatedConn implements flow.LDAPConn using the in-memory directory.
type simulatedConn struct {
	dialer   *simulatedDialer
	boundDN  string
	boundPwd string
}

func (c *simulatedConn) Bind(dn, password string) error {
	// Service account bind (empty credentials allowed for service search).
	if dn == "" {
		c.boundDN = ""
		return nil
	}
	for _, u := range c.dialer.users {
		if u.DN == dn && u.Password == password {
			c.boundDN = dn
			c.boundPwd = password
			return nil
		}
	}
	return errors.New("ldap: invalid credentials")
}

func (c *simulatedConn) Search(req flow.LDAPSearchRequest) ([]flow.LDAPEntry, error) {
	// Parse simple filter like "(uid=alice)".
	attr, val := parseSimpleFilter(req.Filter)
	var results []flow.LDAPEntry
	for _, u := range c.dialer.users {
		vals, ok := u.Attributes[attr]
		if !ok {
			continue
		}
		for _, v := range vals {
			if v == val {
				entry := flow.LDAPEntry{
					DN:         u.DN,
					Attributes: make(map[string][]string),
				}
				for _, reqAttr := range req.Attributes {
					if attrVals, ok := u.Attributes[reqAttr]; ok {
						entry.Attributes[reqAttr] = attrVals
					}
				}
				results = append(results, entry)
			}
		}
	}
	return results, nil
}

func (c *simulatedConn) Close() error { return nil }

// parseSimpleFilter extracts attr and value from "(attr=value)".
func parseSimpleFilter(filter string) (attr, value string) {
	s := strings.TrimPrefix(filter, "(")
	s = strings.TrimSuffix(s, ")")
	parts := strings.SplitN(s, "=", 2)
	if len(parts) == 2 {
		return parts[0], parts[1]
	}
	return "", ""
}

// ---------- In-memory IdentityStorage ----------

// ---------- Server ----------

type server struct {
	repo     *kayantesting.MemoryStore
	login    *flow.LoginManager
	sessions *session.JWTStrategy
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

// POST /api/ldap/login – { username, password } → { session_token }
// LDAPStrategy: binds as service account → searches for user DN → re-binds as user.
func (s *server) handleLogin(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var body struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.Username == "" || body.Password == "" {
		writeError(w, http.StatusBadRequest, "username and password required")
		return
	}

	// LDAPStrategy.Authenticate: connects via DialTLS, binds service acct, searches user,
	// re-binds as user to verify password, then maps LDAP attrs → identity traits.
	identRaw, err := s.login.Authenticate(r.Context(), "ldap", body.Username, body.Password)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "invalid credentials")
		return
	}

	ident := identRaw.(*identity.Identity)
	// Persist the identity so /api/me can look it up later.
	_ = s.repo.CreateIdentity(ctx, ident)

	sess, err := s.sessions.Create(ctx, uuid.New().String(), fmt.Sprintf("%v", ident.GetID()))
	if err != nil {
		writeError(w, http.StatusInternalServerError, "session error")
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"session_token": sess.ID})
}

// GET /api/me – Authorization: Bearer <session_token>
func (s *server) handleMe(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	token := bearerToken(r)
	sess, err := s.sessions.Validate(ctx, token)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "invalid or expired session")
		return
	}
	identRaw, err := s.repo.GetIdentity(ctx, func() any { return &identity.Identity{} }, sess.IdentityID)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "identity not found")
		return
	}
	ident := identRaw.(*identity.Identity)
	var m map[string]any
	_ = json.Unmarshal(ident.Traits, &m)
	writeJSON(w, http.StatusOK, map[string]any{
		"id":     fmt.Sprintf("%v", ident.GetID()),
		"traits": m,
	})
}

// ---------- Main ----------

func main() {
	repo := kayantesting.NewMemoryStore()
	factory := func() any {
		return &identity.Identity{ID: uuid.New().String()}
	}

	dialer := newSimulatedDialer()

	// flow.NewLDAPStrategy: uses LDAPDialer to open connection, searches by uid,
	// maps LDAP "mail" attribute to Kayan identity trait "email".
	ldapStrategy := flow.NewLDAPStrategy(dialer, flow.LDAPConfig{
		Addr:                   "ldap.example.com:636",
		BaseDN:                 "ou=users,dc=example,dc=com",
		UsernameAttribute:      "uid",
		ServiceAccountDN:       "",
		ServiceAccountPassword: "",
		TraitAttributes: map[string]string{
			"email": "mail",
			"name":  "cn",
		},
	}, factory)

	login := flow.NewLoginManager(repo, factory)
	login.RegisterStrategy(ldapStrategy)

	jwtStrategy := session.NewHS256Strategy(sessionSecret(), 24*time.Hour)

	srv := &server{repo: repo, login: login, sessions: jwtStrategy}

	mux := http.NewServeMux()
	mux.HandleFunc("POST /api/ldap/login", srv.handleLogin)
	mux.HandleFunc("GET /api/me", srv.handleMe)

	log.Println("10-ldap backend listening on :8080 (simulated LDAP: alice/alice123, bob/bob456)")
	if err := http.ListenAndServe(":8080", corsMiddleware(mux)); err != nil {
		log.Fatal(err)
	}
}

// sessionSecret reads the signing secret from the environment.
//
// Examples used to hardcode one. That string is the most-copied line in a
// sample application, and it ends up signing real sessions.
func sessionSecret() string {
	secret := os.Getenv("SESSION_SECRET")
	if secret == "" {
		log.Fatal("SESSION_SECRET is not set. Generate one with: openssl rand -base64 32")
	}
	return secret
}
