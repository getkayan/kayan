package flow

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/getkayan/kayan/core/identity"
)

// ---- mock LDAP ----

type mockLDAPConn struct {
	binds   []string // DN:password pairs recorded
	entries []LDAPEntry
	bindErr map[string]error // DN → error
	// searchErr makes the directory refuse the search, which is how an
	// outage, a wrong base DN, or a size-limit refusal reaches the strategy.
	searchErr error
	closed    bool

	// lastSearch records what the strategy asked for. Whether the request
	// carries a size limit is not observable from the returned entries, and
	// it is the part that stops a broad filter streaming a whole subtree.
	lastSearch LDAPSearchRequest
}

func (c *mockLDAPConn) Bind(dn, password string) error {
	key := dn + ":" + password
	c.binds = append(c.binds, key)
	if err, ok := c.bindErr[dn]; ok {
		return err
	}
	return nil
}

// Search models a real directory: it enforces the requested size limit and
// reports the truncation rather than returning a short result that reads as
// complete.
func (c *mockLDAPConn) Search(req LDAPSearchRequest) ([]LDAPEntry, error) {
	c.lastSearch = req
	if c.searchErr != nil {
		return nil, c.searchErr
	}
	if req.SizeLimit > 0 && len(c.entries) > req.SizeLimit {
		return c.entries[:req.SizeLimit], fmt.Errorf("mock: %w", ErrLDAPResultTruncated)
	}
	return c.entries, nil
}

func (c *mockLDAPConn) Close() error {
	c.closed = true
	return nil
}

type mockLDAPDialer struct {
	conn    *mockLDAPConn
	dialErr error

	// perAddr lets a test model an estate: one replica down, another serving.
	perAddr map[string]*mockLDAPConn
	// dialed records every address tried, in order, which is the only way to
	// see whether a failure moved on to the next host.
	dialed []string
}

func (d *mockLDAPDialer) DialTLS(ctx context.Context, addr string) (LDAPConn, error) {
	d.dialed = append(d.dialed, addr)
	if d.perAddr != nil {
		conn, ok := d.perAddr[addr]
		if !ok {
			return nil, errors.New("connection refused")
		}
		return conn, nil
	}
	if d.dialErr != nil {
		return nil, d.dialErr
	}
	return d.conn, nil
}

// ---- tests ----

func defaultLDAPConfig() LDAPConfig {
	return LDAPConfig{
		Addr:                   "ldap.example.com:636",
		BaseDN:                 "ou=users,dc=example,dc=com",
		UsernameAttribute:      "uid",
		ServiceAccountDN:       "cn=svc,dc=example,dc=com",
		ServiceAccountPassword: "svcpass",
		TraitAttributes:        map[string]string{"email": "mail", "name": "cn"},
	}
}

func TestLDAPStrategy_ID(t *testing.T) {
	s := NewLDAPStrategy(nil, LDAPConfig{}, nil)
	if s.ID() != "ldap" {
		t.Errorf("ID() = %q, want %q", s.ID(), "ldap")
	}
}

func TestLDAPStrategy_Authenticate(t *testing.T) {
	tests := []struct {
		name      string
		username  string
		password  string
		setupConn func(*mockLDAPConn)
		dialErr   error
		wantErr   error
	}{
		{
			name:     "valid credentials",
			username: "alice",
			password: "alicepass",
		},
		{
			name:    "empty username",
			wantErr: ErrLDAPInvalidCredentials,
		},
		{
			name:     "empty password",
			username: "alice",
			wantErr:  ErrLDAPInvalidCredentials,
		},
		{
			name:     "dial failure",
			username: "alice", password: "alicepass",
			dialErr: errors.New("connection refused"),
			wantErr: ErrLDAPConnectionFailed,
		},
		{
			name:     "service account bind failure",
			username: "alice", password: "alicepass",
			setupConn: func(c *mockLDAPConn) {
				c.bindErr["cn=svc,dc=example,dc=com"] = errors.New("auth failed")
			},
			wantErr: ErrLDAPConnectionFailed,
		},
		{
			name:     "user not found",
			username: "ghost", password: "pass",
			setupConn: func(c *mockLDAPConn) { c.entries = nil },
			wantErr:   ErrLDAPUserNotFound,
		},
		{
			name:     "wrong password",
			username: "alice", password: "wrongpass",
			setupConn: func(c *mockLDAPConn) {
				c.bindErr["uid=alice,ou=users,dc=example,dc=com"] = errors.New("invalid credentials")
			},
			wantErr: ErrLDAPInvalidCredentials,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			conn := &mockLDAPConn{
				bindErr: make(map[string]error),
				entries: []LDAPEntry{
					{
						DN: "uid=alice,ou=users,dc=example,dc=com",
						Attributes: map[string][]string{
							"mail": {"alice@example.com"},
							"cn":   {"Alice"},
						},
					},
				},
			}
			if tt.setupConn != nil {
				tt.setupConn(conn)
			}

			dialer := &mockLDAPDialer{conn: conn, dialErr: tt.dialErr}
			s := NewLDAPStrategy(dialer, defaultLDAPConfig(), func() any { return &mockIdentity{} })
			got, err := s.Authenticate(context.Background(), tt.username, tt.password)

			if tt.wantErr != nil {
				if !errors.Is(err, tt.wantErr) {
					t.Errorf("error = %v, wantErr %v", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got == nil {
				t.Error("expected identity, got nil")
			}
		})
	}
}

func TestLDAPStrategy_ClosesConnection(t *testing.T) {
	conn := &mockLDAPConn{
		bindErr: make(map[string]error),
		entries: []LDAPEntry{{DN: "uid=alice,ou=users,dc=example,dc=com", Attributes: map[string][]string{}}},
	}
	dialer := &mockLDAPDialer{conn: conn}
	s := NewLDAPStrategy(dialer, defaultLDAPConfig(), func() any { return &mockIdentity{} })
	s.Authenticate(context.Background(), "alice", "alicepass") //nolint:errcheck
	if !conn.closed {
		t.Error("connection was not closed after Authenticate")
	}
}

func TestEscapeLDAPFilter(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"alice", "alice"},
		{"al*ce", "al\\2ace"},
		{"a(b)c", "a\\28b\\29c"},
		{"a\\b", "a\\5cb"},
		{"a\x00b", "a\\00b"},
	}
	for _, tt := range tests {
		got := escapeLDAPFilter(tt.input)
		if got != tt.want {
			t.Errorf("escapeLDAPFilter(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

// mockIdentity for LDAP tests (minimal, implements FlowIdentity + TraitSource)
type mockIdentity struct {
	id     string
	traits identity.JSON
}

func (m *mockIdentity) GetID() any                { return m.id }
func (m *mockIdentity) SetID(v any)               { m.id = fmt.Sprintf("%v", v) }
func (m *mockIdentity) GetTraits() identity.JSON  { return m.traits }
func (m *mockIdentity) SetTraits(t identity.JSON) { m.traits = t }

// TestLDAPSearchFailureIsNotReportedAsUserNotFound covers a wrong answer that
// looked exactly like a right one.
//
// The strategy collapsed `err != nil || len(entries) == 0` into
// ErrLDAPUserNotFound, so a directory outage, a mistyped base DN, or Active
// Directory refusing an over-large result all arrived at the application as
// "this user does not exist". Every login in the deployment then failed, the
// user was told their credentials were wrong, and nothing reported that the
// directory was the problem.
func TestLDAPSearchFailureIsNotReportedAsUserNotFound(t *testing.T) {
	outage := errors.New("directory unavailable")
	dialer := &mockLDAPDialer{conn: &mockLDAPConn{searchErr: outage}}
	strategy := NewLDAPStrategy(dialer, defaultLDAPConfig(), func() any { return &identity.Identity{} })

	_, err := strategy.Authenticate(context.Background(), "alice", "password")

	if errors.Is(err, ErrLDAPUserNotFound) {
		t.Error("a failed search was reported as a missing user, which blames the " +
			"end user for a directory fault")
	}
	if !errors.Is(err, ErrLDAPSearchFailed) {
		t.Errorf("error = %v, want ErrLDAPSearchFailed", err)
	}
	if !strings.Contains(err.Error(), "directory unavailable") {
		t.Errorf("error = %v, want it to carry the underlying cause", err)
	}
}

// TestLDAPEmptyResultIsStillUserNotFound keeps the distinction meaningful in
// the other direction: a search that ran and matched nobody is a real
// not-found, not a failure.
func TestLDAPEmptyResultIsStillUserNotFound(t *testing.T) {
	dialer := &mockLDAPDialer{conn: &mockLDAPConn{entries: nil}}
	strategy := NewLDAPStrategy(dialer, defaultLDAPConfig(), func() any { return &identity.Identity{} })

	_, err := strategy.Authenticate(context.Background(), "nobody", "password")
	if !errors.Is(err, ErrLDAPUserNotFound) {
		t.Errorf("error = %v, want ErrLDAPUserNotFound", err)
	}
	if errors.Is(err, ErrLDAPSearchFailed) {
		t.Error("an empty result was reported as a search failure")
	}
}

// TestLDAPFailureCausesSurvive covers the diagnosis path. Each sentinel keeps
// the decision stable for the caller while carrying what an operator needs.
func TestLDAPFailureCausesSurvive(t *testing.T) {
	dialFault := errors.New("connection refused")
	dialer := &mockLDAPDialer{dialErr: dialFault}
	strategy := NewLDAPStrategy(dialer, defaultLDAPConfig(), func() any { return &identity.Identity{} })

	_, err := strategy.Authenticate(context.Background(), "alice", "password")
	if !errors.Is(err, ErrLDAPConnectionFailed) {
		t.Fatalf("error = %v, want ErrLDAPConnectionFailed", err)
	}
	if !strings.Contains(err.Error(), "connection refused") {
		t.Errorf("error = %v, want it to carry the dial failure", err)
	}
}

// TestLDAPServiceAccountFailureIsNotTheUsersFault covers a misconfiguration
// that rejects every login in the deployment. It must not read as a problem
// with the credentials the end user supplied.
func TestLDAPServiceAccountFailureIsNotTheUsersFault(t *testing.T) {
	rejected := errors.New("service bind rejected")
	conn := &mockLDAPConn{bindErr: map[string]error{"cn=svc,dc=example,dc=com": rejected}}
	strategy := NewLDAPStrategy(&mockLDAPDialer{conn: conn},
		defaultLDAPConfig(), func() any { return &identity.Identity{} })

	_, err := strategy.Authenticate(context.Background(), "alice", "password")
	if errors.Is(err, ErrLDAPInvalidCredentials) {
		t.Error("a rejected service-account bind was reported as the end user's " +
			"credentials being wrong")
	}
	if !errors.Is(err, ErrLDAPConnectionFailed) {
		t.Errorf("error = %v, want ErrLDAPConnectionFailed", err)
	}
	if !strings.Contains(err.Error(), "service account") {
		t.Errorf("error = %v, want it to name the service account bind", err)
	}
}

// TestLDAPDuplicateUsernameIsRefused is the central test for the ambiguity
// fix.
//
// The strategy took entries[0] from the search result. LDAP enforces no
// uniqueness on uid or sAMAccountName -- OpenLDAP has no unique constraint
// unless the uniqueness overlay is configured -- and a subtree search spans
// every OU beneath the base DN. So a second entry carrying the victim's
// username, in any OU the attacker can write to, put the attacker's DN into
// the result set. Whichever entry the server listed first is the DN the
// password was then checked against, which meant an attacker's own password
// could authenticate a login for the victim's username, and which entry won
// depended on the replica that served the search.
func TestLDAPDuplicateUsernameIsRefused(t *testing.T) {
	conn := &mockLDAPConn{entries: []LDAPEntry{
		{DN: "uid=alice,ou=contractors,dc=example,dc=com",
			Attributes: map[string][]string{"mail": {"attacker@evil.test"}}},
		{DN: "uid=alice,ou=staff,dc=example,dc=com",
			Attributes: map[string][]string{"mail": {"alice@example.com"}}},
	}}
	strategy := NewLDAPStrategy(&mockLDAPDialer{conn: conn},
		defaultLDAPConfig(), func() any { return &identity.Identity{} })

	ident, err := strategy.Authenticate(context.Background(), "alice", "password")

	if err == nil {
		t.Fatal("authenticated against one of two entries sharing the username")
	}
	if ident != nil {
		t.Error("an identity was returned for an ambiguous username; a caller " +
			"reading only the identity would mint a session for it")
	}
	if !errors.Is(err, ErrLDAPAmbiguousUser) {
		t.Errorf("error = %v, want ErrLDAPAmbiguousUser", err)
	}

	// The user bind must never have been attempted. Reaching it means a DN was
	// chosen, and choosing is the defect.
	for _, bind := range conn.binds {
		if strings.HasPrefix(bind, "uid=alice,") {
			t.Errorf("bound as %q; the strategy picked a DN out of an ambiguous result", bind)
		}
	}
}

// TestLDAPTruncatedResultIsAmbiguousNotAnOutage covers the same defect arriving
// as an error instead of a list.
//
// Active Directory applies MaxPageSize -- 1000 by default -- to a search
// without the paged-results control, and the strategy caps its own search at
// two entries. Either way a third match reaches the strategy as a truncation,
// which is evidence of ambiguity, not of a broken directory.
func TestLDAPTruncatedResultIsAmbiguousNotAnOutage(t *testing.T) {
	conn := &mockLDAPConn{entries: []LDAPEntry{
		{DN: "uid=alice,ou=a,dc=example,dc=com"},
		{DN: "uid=alice,ou=b,dc=example,dc=com"},
		{DN: "uid=alice,ou=c,dc=example,dc=com"},
	}}
	strategy := NewLDAPStrategy(&mockLDAPDialer{conn: conn},
		defaultLDAPConfig(), func() any { return &identity.Identity{} })

	_, err := strategy.Authenticate(context.Background(), "alice", "password")
	if !errors.Is(err, ErrLDAPAmbiguousUser) {
		t.Errorf("error = %v, want ErrLDAPAmbiguousUser", err)
	}
	if errors.Is(err, ErrLDAPSearchFailed) {
		t.Error("a truncated result was reported as a search failure, which hides " +
			"a duplicate username behind what looks like an outage")
	}
}

// TestLDAPSearchIsSizeLimited proves the request carries the cap. Without it
// a filter that unexpectedly matches broadly -- a wildcard username attribute,
// a base DN pointed at the directory root -- streams the whole subtree into
// memory before anything rejects it.
func TestLDAPSearchIsSizeLimited(t *testing.T) {
	conn := &mockLDAPConn{entries: []LDAPEntry{{DN: "uid=alice,ou=staff,dc=example,dc=com"}}}
	strategy := NewLDAPStrategy(&mockLDAPDialer{conn: conn},
		defaultLDAPConfig(), func() any { return &identity.Identity{} })

	if _, err := strategy.Authenticate(context.Background(), "alice", "password"); err != nil {
		t.Fatalf("Authenticate() error = %v", err)
	}
	if conn.lastSearch.SizeLimit != 2 {
		t.Errorf("SizeLimit = %d, want 2: enough to detect a second match, "+
			"not enough to pull a subtree", conn.lastSearch.SizeLimit)
	}
}

// TestLDAPSingleMatchStillAuthenticates keeps the fix from being a blanket
// refusal. The ordinary case -- one entry, correct password -- must still
// succeed, or the test above would pass against a strategy that rejects
// everything.
func TestLDAPSingleMatchStillAuthenticates(t *testing.T) {
	conn := &mockLDAPConn{entries: []LDAPEntry{
		{DN: "uid=alice,ou=staff,dc=example,dc=com",
			Attributes: map[string][]string{"mail": {"alice@example.com"}}},
	}}
	strategy := NewLDAPStrategy(&mockLDAPDialer{conn: conn},
		defaultLDAPConfig(), func() any { return &identity.Identity{} })

	ident, err := strategy.Authenticate(context.Background(), "alice", "password")
	if err != nil {
		t.Fatalf("Authenticate() error = %v", err)
	}
	if ident == nil {
		t.Fatal("Authenticate() returned no identity for a single exact match")
	}
	if len(conn.binds) != 2 {
		t.Errorf("binds = %v, want the service account bind then the user bind", conn.binds)
	}
}
