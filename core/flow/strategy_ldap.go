package flow

import (
	"context"
	"fmt"

	"github.com/getkayan/kayan/core/identity"
)

// LDAPDialer is the interface for opening an LDAP connection.
// Inject a real implementation backed by github.com/go-ldap/ldap/v3 in your adapter.
// core/ never imports the ldap package directly.
type LDAPDialer interface {
	// DialTLS opens a TLS-encrypted LDAP connection to addr.
	// Implementations should reject plain-text connections unless in test mode.
	DialTLS(ctx context.Context, addr string) (LDAPConn, error)
}

// LDAPConn is a minimal interface over an active LDAP connection.
type LDAPConn interface {
	// Bind authenticates on the connection with dn and password.
	Bind(dn, password string) error
	// Search executes a search and returns matching entries.
	Search(req LDAPSearchRequest) ([]LDAPEntry, error)
	// Close releases the connection.
	Close() error
}

// LDAPSearchRequest carries parameters for an LDAP search.
type LDAPSearchRequest struct {
	BaseDN     string
	Filter     string // e.g. "(uid=alice)"
	Attributes []string
}

// LDAPEntry is a single LDAP directory entry returned by Search.
type LDAPEntry struct {
	DN         string
	Attributes map[string][]string
}

// LDAPConfig holds the configuration for the ldap strategy.
type LDAPConfig struct {
	// Addr is the LDAP server address (host:port), e.g. "ldap.example.com:636".
	Addr string
	// BaseDN is the base distinguished name for user searches, e.g. "ou=users,dc=example,dc=com".
	BaseDN string
	// UsernameAttribute is the LDAP attribute used for user search, e.g. "uid" or "sAMAccountName".
	UsernameAttribute string
	// ServiceAccountDN is the DN used for the initial bind/search (read-only service account).
	ServiceAccountDN string
	// ServiceAccountPassword is the service account's password. Never log this.
	ServiceAccountPassword string
	// TraitAttributes maps Kayan trait names to LDAP attribute names, e.g. {"email": "mail"}.
	TraitAttributes map[string]string
}

// LDAPStrategy is a single-step LoginStrategy that authenticates against an LDAP / Active Directory server.
//
// Flow:
//  1. Bind as service account to search for the user's DN.
//  2. Re-bind as the user with the provided password to verify credentials.
//  3. Map LDAP attributes to a Kayan identity (optionally sync on first login).
//
// Security invariants:
//   - Always uses TLS (via LDAPDialer.DialTLS).
//   - Service account password and user password are never logged.
//   - The user password is verified server-side by the LDAP bind — it is never stored.
type LDAPStrategy struct {
	dialer  LDAPDialer
	config  LDAPConfig
	factory func() any
}

// NewLDAPStrategy creates an LDAPStrategy.
//
//	strategy := flow.NewLDAPStrategy(dialer, cfg, func() any { return &User{} })
//	loginManager.RegisterStrategy(strategy)
func NewLDAPStrategy(dialer LDAPDialer, config LDAPConfig, factory func() any) *LDAPStrategy {
	return &LDAPStrategy{dialer: dialer, config: config, factory: factory}
}

func (s *LDAPStrategy) ID() string { return "ldap" }

// Authenticate looks up the user in LDAP (via service-account bind) then
// re-binds as that user to verify the supplied password.
func (s *LDAPStrategy) Authenticate(ctx context.Context, username, password string) (any, error) {
	if username == "" || password == "" {
		return nil, ErrLDAPInvalidCredentials
	}

	conn, err := s.dialer.DialTLS(ctx, s.config.Addr)
	if err != nil {
		return nil, ErrLDAPConnectionFailed
	}
	defer conn.Close()

	// Step 1: bind as service account to search for the user DN.
	if err := conn.Bind(s.config.ServiceAccountDN, s.config.ServiceAccountPassword); err != nil {
		return nil, ErrLDAPConnectionFailed
	}

	filter := fmt.Sprintf("(%s=%s)", s.config.UsernameAttribute, escapeLDAPFilter(username))
	entries, err := conn.Search(LDAPSearchRequest{
		BaseDN: s.config.BaseDN,
		Filter: filter,
	})
	if err != nil || len(entries) == 0 {
		return nil, ErrLDAPUserNotFound
	}

	userDN := entries[0].DN

	// Step 2: re-bind as the user to verify their password.
	if err := conn.Bind(userDN, password); err != nil {
		return nil, ErrLDAPInvalidCredentials
	}

	// Step 3: map LDAP attributes to a Kayan identity.
	return s.mapEntry(entries[0]), nil
}

// mapEntry converts an LDAP entry into a Kayan identity via the factory.
func (s *LDAPStrategy) mapEntry(entry LDAPEntry) any {
	ident := s.factory()

	// If the identity supports traits, populate them from mapped attributes.
	if ts, ok := ident.(TraitSource); ok {
		traits := make(map[string]string, len(s.config.TraitAttributes))
		for traitKey, ldapAttr := range s.config.TraitAttributes {
			if vals, ok := entry.Attributes[ldapAttr]; ok && len(vals) > 0 {
				traits[traitKey] = vals[0]
			}
		}
		// Build JSON traits
		raw := buildJSONTraits(traits)
		ts.SetTraits(identity.JSON(raw))
	}

	return ident
}

// escapeLDAPFilter escapes special characters in an LDAP filter value per RFC 4515.
func escapeLDAPFilter(s string) string {
	escaped := make([]byte, 0, len(s))
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '\\':
			escaped = append(escaped, '\\', '5', 'c')
		case '*':
			escaped = append(escaped, '\\', '2', 'a')
		case '(':
			escaped = append(escaped, '\\', '2', '8')
		case ')':
			escaped = append(escaped, '\\', '2', '9')
		case '\x00':
			escaped = append(escaped, '\\', '0', '0')
		default:
			escaped = append(escaped, s[i])
		}
	}
	return string(escaped)
}

// buildJSONTraits constructs a minimal JSON object from a string map.
func buildJSONTraits(m map[string]string) string {
	if len(m) == 0 {
		return "{}"
	}
	result := "{"
	first := true
	for k, v := range m {
		if !first {
			result += ","
		}
		result += fmt.Sprintf("%q:%q", k, v)
		first = false
	}
	result += "}"
	return result
}
