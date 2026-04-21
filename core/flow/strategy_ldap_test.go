package flow

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/getkayan/kayan/core/identity"
)

// ---- mock LDAP ----

type mockLDAPConn struct {
	binds   []string // DN:password pairs recorded
	entries []LDAPEntry
	bindErr map[string]error // DN → error
	closed  bool
}

func (c *mockLDAPConn) Bind(dn, password string) error {
	key := dn + ":" + password
	c.binds = append(c.binds, key)
	if err, ok := c.bindErr[dn]; ok {
		return err
	}
	return nil
}

func (c *mockLDAPConn) Search(req LDAPSearchRequest) ([]LDAPEntry, error) {
	return c.entries, nil
}

func (c *mockLDAPConn) Close() error {
	c.closed = true
	return nil
}

type mockLDAPDialer struct {
	conn    *mockLDAPConn
	dialErr error
}

func (d *mockLDAPDialer) DialTLS(ctx context.Context, addr string) (LDAPConn, error) {
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
