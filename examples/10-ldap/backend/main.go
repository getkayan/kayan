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
	"log"
	"net/http"
	"reflect"
	"strings"
	"sync"
	"time"

	"github.com/getkayan/kayan/core/flow"
	"github.com/getkayan/kayan/core/identity"
	"github.com/getkayan/kayan/core/session"
	"github.com/google/uuid"
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

type memRepo struct {
	mu         sync.RWMutex
	identities map[string]any
	creds      map[string]*identity.Credential
}

func newMemRepo() *memRepo {
	return &memRepo{
		identities: make(map[string]any),
		creds:      make(map[string]*identity.Credential),
	}
}

func (r *memRepo) CreateIdentity(ident any) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if fi, ok := ident.(flow.FlowIdentity); ok {
		r.identities[fmt.Sprintf("%v", fi.GetID())] = ident
	}
	return nil
}

func (r *memRepo) GetIdentity(factory func() any, id any) (any, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	v, ok := r.identities[fmt.Sprintf("%v", id)]
	if !ok {
		return nil, errors.New("identity not found")
	}
	return v, nil
}

func (r *memRepo) FindIdentity(factory func() any, query map[string]any) (any, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	for _, ident := range r.identities {
		v := reflect.ValueOf(ident)
		if v.Kind() == reflect.Ptr {
			v = v.Elem()
		}
		match := true
		for field, value := range query {
			f := v.FieldByName(field)
			if !f.IsValid() || fmt.Sprintf("%v", f.Interface()) != fmt.Sprintf("%v", value) {
				match = false
				break
			}
		}
		if match {
			return ident, nil
		}
	}
	return nil, errors.New("identity not found")
}

func (r *memRepo) ListIdentities(factory func() any, page, limit int) ([]any, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]any, 0, len(r.identities))
	for _, v := range r.identities {
		out = append(out, v)
	}
	return out, nil
}

func (r *memRepo) UpdateIdentity(ident any) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if fi, ok := ident.(flow.FlowIdentity); ok {
		r.identities[fmt.Sprintf("%v", fi.GetID())] = ident
	}
	return nil
}

func (r *memRepo) DeleteIdentity(factory func() any, id any) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.identities, fmt.Sprintf("%v", id))
	return nil
}

func (r *memRepo) CreateCredential(cred any) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if c, ok := cred.(*identity.Credential); ok {
		r.creds[c.Identifier+":"+c.Type] = c
	}
	return nil
}

func (r *memRepo) GetCredentialByIdentifier(identifier, method string) (*identity.Credential, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	if method == "" {
		for key, c := range r.creds {
			if strings.HasPrefix(key, identifier+":") {
				return c, nil
			}
		}
		return nil, errors.New("credential not found")
	}
	c, ok := r.creds[identifier+":"+method]
	if !ok {
		return nil, errors.New("credential not found")
	}
	return c, nil
}

func (r *memRepo) UpdateCredentialSecret(_ context.Context, identityID, method, secret string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, c := range r.creds {
		if c.IdentityID == identityID && c.Type == method {
			c.Secret = secret
			return nil
		}
	}
	return errors.New("credential not found")
}

// ---------- Server ----------

type server struct {
	repo     *memRepo
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
	_ = s.repo.CreateIdentity(ident)

	sess, err := s.sessions.Create(uuid.New().String(), fmt.Sprintf("%v", ident.GetID()))
	if err != nil {
		writeError(w, http.StatusInternalServerError, "session error")
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"session_token": sess.ID})
}

// GET /api/me – Authorization: Bearer <session_token>
func (s *server) handleMe(w http.ResponseWriter, r *http.Request) {
	token := bearerToken(r)
	sess, err := s.sessions.Validate(token)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "invalid or expired session")
		return
	}
	identRaw, err := s.repo.GetIdentity(func() any { return &identity.Identity{} }, sess.IdentityID)
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
	repo := newMemRepo()
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

	jwtStrategy := session.NewHS256Strategy("change-me-in-production", 24*time.Hour)

	srv := &server{repo: repo, login: login, sessions: jwtStrategy}

	mux := http.NewServeMux()
	mux.HandleFunc("POST /api/ldap/login", srv.handleLogin)
	mux.HandleFunc("GET /api/me", srv.handleMe)

	log.Println("10-ldap backend listening on :8080 (simulated LDAP: alice/alice123, bob/bob456)")
	if err := http.ListenAndServe(":8080", corsMiddleware(mux)); err != nil {
		log.Fatal(err)
	}
}
