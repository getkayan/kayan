package ldapstore

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"testing"
	"time"

	"github.com/getkayan/kayan/core/flow"
)

// TestDialerSatisfiesFlowInterface pins the contract. If core/flow changes
// LDAPDialer, this fails at compile time rather than at a customer's login.
func TestDialerSatisfiesFlowInterface(t *testing.T) {
	var _ flow.LDAPDialer = NewDialer()
	var _ flow.LDAPConn = (*Conn)(nil)
}

func TestDefaultTLSConfigIsSecure(t *testing.T) {
	d := NewDialer()

	if d.tlsConfig == nil {
		t.Fatal("no TLS configuration")
	}
	if d.tlsConfig.InsecureSkipVerify {
		t.Error("certificate verification is disabled by default")
	}
	if d.tlsConfig.MinVersion < tls.VersionTLS12 {
		t.Errorf("MinVersion = %x, want at least TLS 1.2", d.tlsConfig.MinVersion)
	}
}

func TestOptions(t *testing.T) {
	t.Run("timeout", func(t *testing.T) {
		d := NewDialer(WithTimeout(3 * time.Second))
		if d.timeout != 3*time.Second {
			t.Errorf("timeout = %v, want 3s", d.timeout)
		}
	})

	t.Run("non-positive timeout falls back to the default", func(t *testing.T) {
		d := NewDialer(WithTimeout(0))
		if d.timeout != DefaultTimeout {
			t.Errorf("timeout = %v, want %v", d.timeout, DefaultTimeout)
		}
	})

	t.Run("root CAs", func(t *testing.T) {
		pool := x509.NewCertPool()
		d := NewDialer(WithRootCAs(pool))
		if d.tlsConfig.RootCAs != pool {
			t.Error("RootCAs was not applied")
		}
		if d.tlsConfig.InsecureSkipVerify {
			t.Error("trusting a custom CA must not disable verification")
		}
	})

	t.Run("custom TLS config", func(t *testing.T) {
		cfg := &tls.Config{MinVersion: tls.VersionTLS13}
		d := NewDialer(WithTLSConfig(cfg))
		if d.tlsConfig != cfg {
			t.Error("TLS configuration was not applied")
		}
	})

	t.Run("insecure skip verify is opt-in only", func(t *testing.T) {
		d := NewDialer(WithInsecureSkipVerify())
		if !d.tlsConfig.InsecureSkipVerify {
			t.Error("WithInsecureSkipVerify had no effect")
		}
		// It must remain impossible to reach this state without asking.
		if NewDialer().tlsConfig.InsecureSkipVerify {
			t.Error("verification is disabled without the explicit option")
		}
	})
}

func TestDialTLSRejectsEmptyAddress(t *testing.T) {
	if _, err := NewDialer().DialTLS(context.Background(), ""); err == nil {
		t.Error("an empty address was accepted")
	}
}

// TestBindRejectsEmptyPassword guards LDAP unauthenticated bind. Many
// directories treat a simple bind with an empty password as success, which
// would authenticate any account whose DN an attacker can guess.
//
// The assertion checks the specific error rather than "any error". Conn has a
// nil *ldap.Conn here, so every path fails somehow; only the guard's own
// message proves the request was refused before it reached the server.
func TestBindRejectsEmptyPassword(t *testing.T) {
	c := &Conn{}

	err := c.Bind("cn=admin,dc=example,dc=com", "")
	if err == nil {
		t.Fatal("an empty password was accepted; this is an LDAP unauthenticated bind")
	}
	if !contains(err.Error(), "empty bind password") {
		t.Fatalf("error = %v, want the empty-password guard to reject it before dialing", err)
	}
}

func TestBindRejectsEmptyDN(t *testing.T) {
	c := &Conn{}

	err := c.Bind("", "correct-horse-battery-staple")
	if err == nil {
		t.Fatal("an empty bind DN was accepted")
	}
	if !contains(err.Error(), "empty bind DN") {
		t.Errorf("error = %v, want the empty-DN guard", err)
	}
}

// TestBindErrorsOmitCredentials proves a failed bind cannot leak the password
// into logs through the returned error.
func TestBindErrorsOmitCredentials(t *testing.T) {
	const password = "super-secret-password"
	c := &Conn{}

	err := c.Bind("", password)
	if err == nil {
		t.Fatal("expected an error")
	}
	if contains(err.Error(), password) {
		t.Fatalf("the password appears in the error: %v", err)
	}
}

func contains(haystack, needle string) bool {
	if needle == "" {
		return false
	}
	for i := 0; i+len(needle) <= len(haystack); i++ {
		if haystack[i:i+len(needle)] == needle {
			return true
		}
	}
	return false
}
