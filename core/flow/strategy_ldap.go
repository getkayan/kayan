package flow

import (
	"context"
	"errors"
	"fmt"
	"strings"

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

// Service-account authentication methods for [LDAPConfig.ServiceAccountAuth].
const (
	// LDAPServiceAuthSimple binds the service account with a DN and password.
	// This is the default.
	LDAPServiceAuthSimple = ""

	// LDAPServiceAuthExternal binds the service account with SASL EXTERNAL,
	// taking its identity from the TLS client certificate (RFC 4422 appendix
	// A).
	//
	// No service password exists to rotate, leak, or find in a configuration
	// file. It requires a connection presenting a client certificate the
	// directory maps to an account, which is why the dialer refuses it when
	// none is configured: a SASL EXTERNAL bind over a connection with no
	// client certificate is accepted by many directories as anonymous, and an
	// anonymous search returns nothing -- so every login in the deployment
	// fails as "user not found" while the bind reports success.
	LDAPServiceAuthExternal = "external"
)

// LDAPExternalBinder is implemented by connections that can bind with SASL
// EXTERNAL.
//
// It is an optional interface on [LDAPConn] rather than a method on it,
// because a deployment using simple binds needs no such capability and an
// adapter should not have to stub one.
type LDAPExternalBinder interface {
	// BindExternal authenticates the connection from its TLS client
	// certificate.
	BindExternal(ctx context.Context) error
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

	// SizeLimit caps the entries the directory may return. Zero leaves the
	// directory's own limit in force.
	//
	// A search that hits the limit must report [ErrLDAPResultTruncated] along
	// with the entries it did get, never a short result that reads as
	// complete. The distinction is the whole point of the field: a caller that
	// asked "is this username unique?" and silently received the first page of
	// a larger answer would conclude yes.
	SizeLimit int
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

	// FailoverAddrs are additional servers to try when Addr is unreachable,
	// in order. Directory estates run several replicas, and a strategy that
	// knows one address makes any single host's maintenance window an
	// authentication outage.
	//
	// Failover happens only on a connection or search failure. A rejected bind
	// is an answer, not an outage: retrying it against every replica turns one
	// wrong password into one failed-login count per host, so a user who
	// mistypes twice is locked out of a directory configured for three
	// attempts.
	FailoverAddrs []string
	// BaseDN is the base distinguished name for user searches, e.g. "ou=users,dc=example,dc=com".
	BaseDN string
	// UsernameAttribute is the LDAP attribute used for user search, e.g. "uid" or "sAMAccountName".
	UsernameAttribute string
	// ServiceAccountDN is the DN used for the initial bind/search (read-only service account).
	ServiceAccountDN string
	// ServiceAccountPassword is the service account's password. Never log this.
	ServiceAccountPassword string

	// ServiceAccountAuth selects how the service account authenticates:
	// [LDAPServiceAuthSimple] (the default) or [LDAPServiceAuthExternal].
	//
	// It governs only the service-account bind. The end user is always
	// verified by a simple bind with the password they supplied, because that
	// is the credential being checked.
	ServiceAccountAuth string
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

	// Every failure below wraps its cause. The sentinel keeps the decision the
	// caller acts on stable, while the cause is what an operator needs to tell
	// an unreachable directory from a rejected password -- and discarding it
	// left them with neither.
	conn, entries, err := s.lookup(ctx, username)
	if conn != nil {
		defer func() { _ = conn.Close() }()
	}
	// A truncated result is not a failure -- it is the ambiguity answer,
	// arriving as an error because the directory stopped early. Checking it
	// before ErrLDAPSearchFailed keeps a second match from being reported as
	// an outage.
	if errors.Is(err, ErrLDAPResultTruncated) {
		return nil, fmt.Errorf("%w: %q under %q", ErrLDAPAmbiguousUser, username, s.config.BaseDN)
	}
	// A search that failed and a search that found nobody are different
	// answers. Collapsing them reported a directory outage, a wrong base DN,
	// and a size-limit refusal as "this user does not exist", so every login
	// failed with the user blamed and no signal to the operator.
	//
	// lookup has already wrapped its own failures with the right sentinel, so
	// this passes them through rather than relabelling a connection failure as
	// a search failure.
	if err != nil {
		return nil, err
	}
	if len(entries) == 0 {
		return nil, ErrLDAPUserNotFound
	}
	// Taking entries[0] made authentication depend on directory ordering. Two
	// entries sharing the username -- which no directory forbids by default,
	// and which a writable OU anywhere under the base DN is enough to create
	// -- meant the password was checked against whichever DN the server
	// listed first. That is a bind the operator never intended, and it can
	// succeed. There is no safe way to choose between them, so refuse.
	if len(entries) > 1 {
		return nil, fmt.Errorf("%w: %q matched %d entries under %q",
			ErrLDAPAmbiguousUser, username, len(entries), s.config.BaseDN)
	}

	userDN := entries[0].DN

	// Step 2: re-bind as the user to verify their password.
	//
	// The cause is wrapped but the sentinel stays ErrLDAPInvalidCredentials.
	// Telling a rejected password from a connection that dropped mid-bind
	// needs the directory's result code, and core/flow cannot read one without
	// importing an LDAP library -- which the LDAPConn seam exists to avoid. So
	// a caller reading the sentinel is told the safe thing, and an operator
	// reading the wrapped cause can still see a network error for what it is.
	if err := conn.Bind(userDN, password); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrLDAPInvalidCredentials, err)
	}

	// Step 3: map LDAP attributes to a Kayan identity.
	return s.mapEntry(entries[0]), nil
}

// lookup connects to the directory and finds the user, trying each configured
// address in turn.
//
// It returns the live connection so the caller can bind the user on it: the
// bind has to happen against the same server the search answered, or the DN
// that was found may not exist on the host that checks the password.
//
// Only connection-level failures move to the next address. A rejected bind or
// an answered search is a result, and retrying either across the estate turns
// one wrong password into one failed-login count per replica -- a user who
// mistypes twice is locked out of a directory configured for three attempts,
// and nothing in the logs explains the arithmetic.
func (s *LDAPStrategy) lookup(ctx context.Context, username string) (LDAPConn, []LDAPEntry, error) {
	filter := fmt.Sprintf("(%s=%s)", s.config.UsernameAttribute, escapeLDAPFilter(username))
	request := LDAPSearchRequest{
		BaseDN: s.config.BaseDN,
		Filter: filter,
		// Two is every answer this question has: none, exactly one, or more
		// than one. Asking for two is what makes the ambiguity check cheap
		// and, on a filter that unexpectedly matches broadly, stops the
		// directory streaming its whole subtree into memory.
		SizeLimit: 2,
	}

	var failures []string
	// The sentinel reflects the kind of the last failure seen. A directory
	// that answered "search failed" is a different problem from one that never
	// answered at all, and collapsing every exhausted-estate case into
	// "connection failed" would undo that distinction for the single-server
	// deployment, which is most of them.
	lastKind := ErrLDAPConnectionFailed

	for _, addr := range s.addresses() {
		conn, err := s.dialer.DialTLS(ctx, addr)
		if err != nil {
			failures = append(failures, fmt.Sprintf("%s: %v", addr, err))
			lastKind = ErrLDAPConnectionFailed
			continue
		}

		// Step 1: bind as service account to search for the user DN.
		//
		// A failure here is the service account's, not the end user's: a
		// rotated or mistyped service password rejects every login in the
		// deployment. It is treated as a fault of this host rather than a
		// verdict, since a replica that has not caught up with a password
		// rotation is exactly the case failover should survive.
		if err := s.bindServiceAccount(ctx, conn); err != nil {
			_ = conn.Close()
			failures = append(failures, fmt.Sprintf("%s: service account bind: %v", addr, err))
			lastKind = ErrLDAPConnectionFailed
			continue
		}

		entries, err := conn.Search(request)
		if errors.Is(err, ErrLDAPResultTruncated) {
			// An answer, not a fault: the directory found more than asked
			// for. Every replica would say the same.
			return conn, entries, err
		}
		if err != nil {
			_ = conn.Close()
			failures = append(failures, fmt.Sprintf("%s: search: %v", addr, err))
			lastKind = ErrLDAPSearchFailed
			continue
		}
		return conn, entries, nil
	}

	// Every address is named. An operator reading "connection failed" against
	// a three-replica estate cannot tell one host down from all three, and the
	// two call for very different responses.
	if len(failures) == 0 {
		// No address was configured at all. Reporting it as an unreachable
		// directory would send an operator looking at the network.
		return nil, nil, fmt.Errorf("%w: no directory address is configured", ErrLDAPConnectionFailed)
	}
	return nil, nil, fmt.Errorf("%w: %s", lastKind, strings.Join(failures, "; "))
}

// bindServiceAccount authenticates the connection as the service account.
//
// A configured EXTERNAL bind against a connection that cannot perform one is
// an error, never a fall back to a simple bind. Falling back would send the
// service password over a connection the deployment had decided should carry
// no password, and would do it silently.
func (s *LDAPStrategy) bindServiceAccount(ctx context.Context, conn LDAPConn) error {
	if s.config.ServiceAccountAuth == LDAPServiceAuthExternal {
		binder, ok := conn.(LDAPExternalBinder)
		if !ok {
			return fmt.Errorf("the dialer does not support SASL EXTERNAL, which %q requires",
				LDAPServiceAuthExternal)
		}
		return binder.BindExternal(ctx)
	}
	return conn.Bind(s.config.ServiceAccountDN, s.config.ServiceAccountPassword)
}

// addresses returns the directory addresses to try, in order.
func (s *LDAPStrategy) addresses() []string {
	addrs := make([]string, 0, 1+len(s.config.FailoverAddrs))
	if s.config.Addr != "" {
		addrs = append(addrs, s.config.Addr)
	}
	addrs = append(addrs, s.config.FailoverAddrs...)
	return addrs
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
