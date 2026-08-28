package ldapstore

import (
	"context"
	"crypto/tls"
	"errors"
	"testing"
)

// externalStub records whether an EXTERNAL bind reached the directory.
type externalStub struct {
	stubClient
	externalCalls int
	simpleCalls   int
	externalErr   error
}

func (c *externalStub) ExternalBind() error {
	c.externalCalls++
	return c.externalErr
}

func (c *externalStub) Bind(username, password string) error {
	c.simpleCalls++
	return nil
}

// TestExternalBindRefusedWithoutAClientCertificate is the central test.
//
// SASL EXTERNAL takes the bind identity from the transport. With no client
// certificate there is no identity, and many directories answer such a bind
// with success having mapped it to anonymous. The connection then reports an
// authenticated service account, every search runs with no privileges and
// matches nothing, and every login in the deployment fails as "user not
// found" -- an outage that looks like an empty directory.
func TestExternalBindRefusedWithoutAClientCertificate(t *testing.T) {
	stub := &externalStub{}
	conn := &Conn{conn: stub, hasClientCert: false}

	err := conn.BindExternal(context.Background())
	if err == nil {
		t.Fatal("a SASL EXTERNAL bind was attempted with no client certificate")
	}
	if !errors.Is(err, ErrNoClientCertificate) {
		t.Errorf("error = %v, want ErrNoClientCertificate", err)
	}
	if stub.externalCalls != 0 {
		t.Error("the bind reached the directory, which may answer it as anonymous")
	}
}

// TestExternalBindWithACertificate is the working path.
func TestExternalBindWithACertificate(t *testing.T) {
	stub := &externalStub{}
	conn := &Conn{conn: stub, hasClientCert: true}

	if err := conn.BindExternal(context.Background()); err != nil {
		t.Fatalf("BindExternal: %v", err)
	}
	if stub.externalCalls != 1 {
		t.Errorf("ExternalBind called %d times, want 1", stub.externalCalls)
	}
	if stub.simpleCalls != 0 {
		t.Error("a simple bind was sent as well; an EXTERNAL bind must not carry a password")
	}
}

// TestExternalBindFailureIsNotSwallowed. A directory that refuses the
// certificate must not leave the connection looking authenticated.
func TestExternalBindFailureIsNotSwallowed(t *testing.T) {
	stub := &externalStub{externalErr: errors.New("certificate not mapped to an account")}
	conn := &Conn{conn: stub, hasClientCert: true}

	err := conn.BindExternal(context.Background())
	if err == nil {
		t.Fatal("a refused EXTERNAL bind was reported as success")
	}
	if stub.simpleCalls != 0 {
		t.Error("a simple bind was attempted after EXTERNAL failed; that would send " +
			"the service password over a connection configured to carry none")
	}
}

// TestClientCertificateDetection. A deployment that reloads certificates on
// rotation supplies a callback rather than a static list, and reading that as
// "no certificate" would refuse the configuration that handles rotation
// properly.
func TestClientCertificateDetection(t *testing.T) {
	cases := []struct {
		name string
		cfg  *tls.Config
		want bool
	}{
		{"nil config", nil, false},
		{"no certificates", &tls.Config{MinVersion: tls.VersionTLS12}, false},
		{"static certificate", &tls.Config{
			MinVersion:   tls.VersionTLS12,
			Certificates: []tls.Certificate{{}},
		}, true},
		{"certificate callback", &tls.Config{
			MinVersion: tls.VersionTLS12,
			GetClientCertificate: func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
				return nil, nil
			},
		}, true},
	}

	for _, tc := range cases {
		if got := clientCertificateConfigured(tc.cfg); got != tc.want {
			t.Errorf("%s: got %v, want %v", tc.name, got, tc.want)
		}
	}
}
