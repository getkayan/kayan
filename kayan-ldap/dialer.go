// Package ldapstore connects Kayan's LDAP strategy to a real directory server.
//
// core/flow declares [flow.LDAPDialer] and [flow.LDAPConn] but deliberately
// never imports an LDAP library. This package supplies the implementation,
// backed by github.com/go-ldap/ldap/v3.
//
// # Usage
//
//	dialer := ldapstore.NewDialer()
//	strategy := flow.NewLDAPStrategy(dialer, flow.LDAPConfig{
//	    Addr:                   "ldap.example.com:636",
//	    BaseDN:                 "ou=users,dc=example,dc=com",
//	    UsernameAttribute:      "uid",
//	    ServiceAccountDN:       "cn=svc,dc=example,dc=com",
//	    ServiceAccountPassword: os.Getenv("LDAP_SERVICE_PASSWORD"),
//	    TraitAttributes:        map[string]string{"email": "mail"},
//	}, func() any { return &User{} })
//
//	loginManager.RegisterStrategy(strategy)
//
// # Transport security
//
// [Dialer.DialTLS] requires TLS. LDAP simple bind sends the password in the
// clear, so an unencrypted connection would expose every credential it
// carries. Certificate verification is on by default and can only be
// weakened through explicit options that document what they give up.
package ldapstore

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"time"

	"github.com/getkayan/kayan/core/flow"
	"github.com/go-ldap/ldap/v3"
)

// Errors reported by this package.
var (
	// ErrTLSRequired reports an attempt to connect without TLS.
	ErrTLSRequired = errors.New("ldapstore: TLS is required")
)

// DefaultTimeout bounds connection and search operations when no timeout is
// configured.
const DefaultTimeout = 10 * time.Second

// Dialer opens TLS connections to an LDAP server.
//
// It implements [flow.LDAPDialer]. The zero value is not usable; call
// [NewDialer].
type Dialer struct {
	startTLS  bool
	tlsConfig *tls.Config
	timeout   time.Duration
}

var _ flow.LDAPDialer = (*Dialer)(nil)

// DialerOption configures a [Dialer].
type DialerOption func(*Dialer)

// WithTLSConfig replaces the TLS configuration.
//
// Use this to pin a corporate CA or present a client certificate:
//
//	pool := x509.NewCertPool()
//	pool.AppendCertsFromPEM(caPEM)
//	ldapstore.NewDialer(ldapstore.WithTLSConfig(&tls.Config{RootCAs: pool}))
func WithTLSConfig(cfg *tls.Config) DialerOption {
	return func(d *Dialer) { d.tlsConfig = cfg }
}

// WithRootCAs trusts pool in addition to the platform roots.
func WithRootCAs(pool *x509.CertPool) DialerOption {
	return func(d *Dialer) {
		if d.tlsConfig == nil {
			d.tlsConfig = &tls.Config{MinVersion: tls.VersionTLS12}
		}
		d.tlsConfig.RootCAs = pool
	}
}

// WithTimeout bounds connection and search operations. Defaults to
// [DefaultTimeout].
func WithTimeout(d time.Duration) DialerOption {
	return func(dialer *Dialer) { dialer.timeout = d }
}

// WithInsecureSkipVerify disables certificate verification.
//
// This makes the connection trivially interceptable: an attacker who can
// answer for the server address receives every password bound through it.
// It exists for development against a self-signed directory. Never enable it
// in production — use [WithRootCAs] to trust an internal CA instead.
func WithInsecureSkipVerify() DialerOption {
	return func(d *Dialer) {
		if d.tlsConfig == nil {
			d.tlsConfig = &tls.Config{MinVersion: tls.VersionTLS12}
		}
		d.tlsConfig.InsecureSkipVerify = true
	}
}

// WithStartTLS connects in the clear and upgrades the connection with StartTLS
// before anything else is sent.
//
// Directories commonly publish port 389 with StartTLS and do not publish 636
// at all, which implicit LDAPS requires. Without this, those directories are
// unreachable and there is no workaround inside the library.
//
// The transport is still encrypted and the certificate is still verified: the
// difference is when the handshake happens, not whether it does. A connection
// whose upgrade fails is closed rather than returned, so no caller can be
// handed a plaintext connection to bind over.
func WithStartTLS() DialerOption {
	return func(d *Dialer) { d.startTLS = true }
}

// NewDialer returns a Dialer that requires TLS 1.2 or better and verifies the
// server certificate against the platform roots.
func NewDialer(opts ...DialerOption) *Dialer {
	d := &Dialer{
		tlsConfig: &tls.Config{MinVersion: tls.VersionTLS12},
		timeout:   DefaultTimeout,
	}
	for _, opt := range opts {
		opt(d)
	}
	if d.tlsConfig == nil {
		d.tlsConfig = &tls.Config{MinVersion: tls.VersionTLS12}
	}
	if d.timeout <= 0 {
		d.timeout = DefaultTimeout
	}
	return d
}

// DialTLS implements [flow.LDAPDialer].
//
// The returned connection is closed when ctx is cancelled, so a caller that
// abandons a login does not leak a directory connection.
func (d *Dialer) DialTLS(ctx context.Context, addr string) (flow.LDAPConn, error) {
	if addr == "" {
		return nil, errors.New("ldapstore: empty address")
	}

	scheme := "ldaps://"
	dialOpts := []ldap.DialOpt{
		ldap.DialWithTLSConfig(d.tlsConfig),
		ldap.DialWithDialer(&net.Dialer{Timeout: d.timeout}),
	}
	if d.startTLS {
		// The plaintext scheme is only the starting point; the upgrade below
		// completes before this function returns a connection to anyone.
		scheme = "ldap://"
	}

	conn, err := ldap.DialURL(scheme+addr, dialOpts...)
	if err != nil {
		// The address is safe to report; anything the server said may quote
		// credentials back, so it is not interpolated here.
		return nil, fmt.Errorf("ldapstore: connect to %s: %w", addr, err)
	}

	conn.SetTimeout(d.timeout)

	if d.startTLS {
		// Upgraded here, before the connection is returned and therefore
		// before any caller can bind on it. A bind over the plaintext leg puts
		// the service account's password, and then the end user's, on the wire
		// in the clear -- so a failed upgrade closes the connection rather
		// than returning one that looks usable.
		if err := conn.StartTLS(d.tlsConfig); err != nil {
			_ = conn.Close()
			return nil, fmt.Errorf("ldapstore: StartTLS upgrade to %s failed: %w", addr, err)
		}
		if state, ok := conn.TLSConnectionState(); !ok || !state.HandshakeComplete {
			// Belt to the error check above: a StartTLS that reports success
			// without a completed handshake would leave the caller binding in
			// the clear while believing the transport is encrypted.
			_ = conn.Close()
			return nil, fmt.Errorf("ldapstore: StartTLS to %s did not complete a handshake", addr)
		}
	}

	c := &Conn{conn: conn, timeout: d.timeout}
	c.watch(ctx)
	return c, nil
}

// Conn is an active LDAP connection.
//
// It implements [flow.LDAPConn].
type Conn struct {
	conn    *ldap.Conn
	timeout time.Duration
	done    chan struct{}
}

var _ flow.LDAPConn = (*Conn)(nil)

// watch closes the connection when ctx is cancelled.
func (c *Conn) watch(ctx context.Context) {
	if ctx == nil || ctx.Done() == nil {
		return
	}
	c.done = make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			_ = c.conn.Close()
		case <-c.done:
		}
	}()
}

// Bind authenticates on the connection.
//
// The password is passed to the server and never logged, stored, or included
// in a returned error.
func (c *Conn) Bind(dn, password string) error {
	if dn == "" {
		return errors.New("ldapstore: empty bind DN")
	}
	// An empty password triggers an LDAP unauthenticated bind, which many
	// directories accept as success — it would authenticate any account whose
	// DN is known. Reject it before it reaches the server.
	if password == "" {
		return errors.New("ldapstore: empty bind password")
	}

	if err := c.conn.Bind(dn, password); err != nil {
		// The server's message can echo the DN; the password never appears in
		// it, but the error is still wrapped rather than surfaced verbatim.
		return fmt.Errorf("ldapstore: bind failed: %w", err)
	}
	return nil
}

// Search executes an LDAP search.
func (c *Conn) Search(req flow.LDAPSearchRequest) ([]flow.LDAPEntry, error) {
	search := ldap.NewSearchRequest(
		req.BaseDN,
		ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases,
		0, // no size limit; the directory's own limit applies
		int(c.timeout.Seconds()),
		false,
		req.Filter,
		req.Attributes,
		nil,
	)

	result, err := c.conn.Search(search)
	if err != nil {
		return nil, fmt.Errorf("ldapstore: search: %w", err)
	}

	entries := make([]flow.LDAPEntry, 0, len(result.Entries))
	for _, e := range result.Entries {
		attrs := make(map[string][]string, len(e.Attributes))
		for _, a := range e.Attributes {
			attrs[a.Name] = a.Values
		}
		entries = append(entries, flow.LDAPEntry{DN: e.DN, Attributes: attrs})
	}
	return entries, nil
}

// Close releases the connection and stops the context watcher.
func (c *Conn) Close() error {
	if c.done != nil {
		close(c.done)
		c.done = nil
	}
	return c.conn.Close()
}
