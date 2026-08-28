package ldapstore

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"

	"github.com/getkayan/kayan/core/flow"
)

// ErrNoClientCertificate reports a SASL EXTERNAL bind attempted over a
// connection that presented no client certificate.
//
// This is the failure worth naming. SASL EXTERNAL takes the bind identity from
// the transport, so with no client certificate there is no identity -- and
// many directories answer such a bind with success, having mapped it to
// anonymous. The connection then reports an authenticated service account,
// every subsequent search runs with no privileges and matches nothing, and
// every login in the deployment fails as "user not found".
var ErrNoClientCertificate = errors.New("ldapstore: SASL EXTERNAL requires a TLS client certificate")

var _ flow.LDAPExternalBinder = (*Conn)(nil)

// BindExternal authenticates the connection with SASL EXTERNAL, taking the
// identity from the TLS client certificate (RFC 4422 appendix A).
//
// It is the alternative to a service-account password: nothing to rotate, leak,
// or find in a configuration file, and the directory decides which account the
// certificate maps to.
//
// Only EXTERNAL is offered. DIGEST-MD5 is obsolete -- RFC 6331 retired it, and
// it requires the directory to hold passwords in a reversible form, which
// trades one stored secret for a worse one. NTLM is legacy and its older
// variants are broken. Adding either would let a deployment believe it had
// moved away from a shared password while doing nothing of the kind.
func (c *Conn) BindExternal(_ context.Context) error {
	// Checked here rather than trusted to the directory, because the
	// directory's answer to a certificate-less EXTERNAL bind is frequently
	// "yes, you are anonymous".
	if !c.hasClientCert {
		return ErrNoClientCertificate
	}
	if err := c.conn.ExternalBind(); err != nil {
		return fmt.Errorf("ldapstore: SASL EXTERNAL bind failed: %w", err)
	}
	return nil
}

// hasClientCertificate reports whether this dialer presents a client
// certificate.
//
// GetClientCertificate counts: a deployment loading certificates from an agent
// or reloading them on rotation supplies a callback rather than a static list,
// and treating that as "no certificate" would refuse the configuration that
// handles rotation properly.
func (d *Dialer) hasClientCertificate() bool {
	cfg := d.tlsConfig
	if cfg == nil {
		return false
	}
	return len(cfg.Certificates) > 0 || cfg.GetClientCertificate != nil
}

// clientCertificateConfigured reports whether cfg presents a client
// certificate. It exists so tests and callers can ask the same question the
// dialer does.
func clientCertificateConfigured(cfg *tls.Config) bool {
	return (&Dialer{tlsConfig: cfg}).hasClientCertificate()
}
