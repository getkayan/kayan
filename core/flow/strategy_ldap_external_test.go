package flow

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/getkayan/kayan/core/identity"
)

// externalConn is a connection that can bind with SASL EXTERNAL.
type externalConn struct {
	*mockLDAPConn
	externalCalls int
	externalErr   error
}

func (c *externalConn) BindExternal(context.Context) error {
	c.externalCalls++
	return c.externalErr
}

// externalDialer hands back a connection that supports EXTERNAL.
type externalDialer struct{ conn *externalConn }

func (d *externalDialer) DialTLS(context.Context, string) (LDAPConn, error) { return d.conn, nil }

func externalConfig() LDAPConfig {
	config := defaultLDAPConfig()
	config.ServiceAccountAuth = LDAPServiceAuthExternal
	return config
}

// TestExternalServiceBindSendsNoPassword is the point of the feature.
//
// SASL EXTERNAL takes the service account's identity from the TLS client
// certificate, so there is no service password to rotate, leak, or find in a
// configuration file. A bind that still sent one would leave the password in
// the deployment while the operator believed it had been removed.
func TestExternalServiceBindSendsNoPassword(t *testing.T) {
	conn := &externalConn{mockLDAPConn: &mockLDAPConn{entries: []LDAPEntry{
		{DN: "uid=alice,ou=staff,dc=example,dc=com"},
	}}}
	strategy := NewLDAPStrategy(&externalDialer{conn: conn}, externalConfig(),
		func() any { return &identity.Identity{} })

	if _, err := strategy.Authenticate(context.Background(), "alice", "password"); err != nil {
		t.Fatalf("Authenticate() error = %v", err)
	}

	if conn.externalCalls != 1 {
		t.Errorf("BindExternal called %d times, want 1", conn.externalCalls)
	}
	for _, bind := range conn.binds {
		if strings.HasPrefix(bind, "cn=svc,") {
			t.Errorf("a simple service bind was sent as %q; the service password "+
				"reached the wire despite EXTERNAL being configured", bind)
		}
	}
}

// TestExternalStillVerifiesTheUserPassword. Only the service bind changes. The
// end user is always checked by a simple bind, because that is the credential
// being verified -- an EXTERNAL bind there would authenticate the service
// account's certificate and call it the user.
func TestExternalStillVerifiesTheUserPassword(t *testing.T) {
	userDN := "uid=alice,ou=staff,dc=example,dc=com"
	conn := &externalConn{mockLDAPConn: &mockLDAPConn{
		entries: []LDAPEntry{{DN: userDN}},
		bindErr: map[string]error{userDN: errors.New("invalid credentials")},
	}}
	strategy := NewLDAPStrategy(&externalDialer{conn: conn}, externalConfig(),
		func() any { return &identity.Identity{} })

	_, err := strategy.Authenticate(context.Background(), "alice", "wrong-password")
	if !errors.Is(err, ErrLDAPInvalidCredentials) {
		t.Errorf("error = %v, want the user password still to be checked", err)
	}
}

// TestExternalDoesNotFallBackToASimpleBind is the security test.
//
// A deployment that configured EXTERNAL decided the connection should carry no
// service password. Falling back when the dialer cannot perform an EXTERNAL
// bind would send that password anyway, silently, over exactly the connection
// it was removed from.
func TestExternalDoesNotFallBackToASimpleBind(t *testing.T) {
	// A plain connection, with no BindExternal method.
	plain := &mockLDAPConn{entries: []LDAPEntry{{DN: "uid=alice,ou=staff,dc=example,dc=com"}}}
	strategy := NewLDAPStrategy(&mockLDAPDialer{conn: plain}, externalConfig(),
		func() any { return &identity.Identity{} })

	_, err := strategy.Authenticate(context.Background(), "alice", "password")
	if err == nil {
		t.Fatal("a configured EXTERNAL bind fell back to a simple one")
	}
	if !errors.Is(err, ErrLDAPConnectionFailed) {
		t.Errorf("error = %v, want ErrLDAPConnectionFailed", err)
	}
	if !strings.Contains(err.Error(), "SASL EXTERNAL") {
		t.Errorf("error = %v, want it to name the missing capability", err)
	}

	for _, bind := range plain.binds {
		if strings.HasPrefix(bind, "cn=svc,") {
			t.Errorf("the service password was sent as %q despite EXTERNAL being configured", bind)
		}
	}
}

// TestExternalBindFailureIsReported. A certificate the directory does not map
// to an account rejects every login in the deployment, so the error must say
// which bind failed rather than blaming the end user.
func TestExternalBindFailureIsReported(t *testing.T) {
	conn := &externalConn{
		mockLDAPConn: &mockLDAPConn{entries: []LDAPEntry{{DN: "uid=alice,ou=x,dc=example,dc=com"}}},
		externalErr:  errors.New("certificate not mapped to an account"),
	}
	strategy := NewLDAPStrategy(&externalDialer{conn: conn}, externalConfig(),
		func() any { return &identity.Identity{} })

	_, err := strategy.Authenticate(context.Background(), "alice", "password")
	if errors.Is(err, ErrLDAPInvalidCredentials) {
		t.Error("a failed service bind was reported as the end user's credentials being wrong")
	}
	if !errors.Is(err, ErrLDAPConnectionFailed) {
		t.Errorf("error = %v, want ErrLDAPConnectionFailed", err)
	}
	if !strings.Contains(err.Error(), "certificate not mapped") {
		t.Errorf("error = %v, want it to carry the directory's cause", err)
	}
}

// TestSimpleServiceBindIsStillTheDefault keeps the change scoped: a deployment
// that configured nothing must behave exactly as before.
func TestSimpleServiceBindIsStillTheDefault(t *testing.T) {
	conn := &externalConn{mockLDAPConn: &mockLDAPConn{entries: []LDAPEntry{
		{DN: "uid=alice,ou=staff,dc=example,dc=com"},
	}}}
	strategy := NewLDAPStrategy(&externalDialer{conn: conn}, defaultLDAPConfig(),
		func() any { return &identity.Identity{} })

	if _, err := strategy.Authenticate(context.Background(), "alice", "password"); err != nil {
		t.Fatalf("Authenticate() error = %v", err)
	}
	if conn.externalCalls != 0 {
		t.Error("an unconfigured deployment used SASL EXTERNAL")
	}
	found := false
	for _, bind := range conn.binds {
		if strings.HasPrefix(bind, "cn=svc,") {
			found = true
		}
	}
	if !found {
		t.Error("the default path did not bind the service account")
	}
}
