package ldapstore

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"strings"
	"testing"
	"time"

	ber "github.com/go-asn1-ber/asn1-ber"
)

// startTLSDirectory answers one StartTLS request and then completes a real
// TLS handshake with a certificate for "localhost" only. The recording
// listener in starttls_test.go never finishes the upgrade, so it cannot show
// whether the handshake itself succeeds.
func startTLSDirectory(t *testing.T) (port string, pool *x509.CertPool) {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "localhost"},
		DNSNames:              []string{"localhost"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	pool = x509.NewCertPool()
	pool.AddCert(cert)
	serverConfig := &tls.Config{
		Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}},
		MinVersion:   tls.VersionTLS12,
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go serveStartTLS(conn, serverConfig)
		}
	}()

	_, port, _ = net.SplitHostPort(ln.Addr().String())
	return port, pool
}

func serveStartTLS(conn net.Conn, config *tls.Config) {
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))

	request, err := ber.ReadPacket(conn)
	if err != nil || len(request.Children) < 1 {
		return
	}
	messageID, _ := request.Children[0].Value.(int64)

	response := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "LDAP Response")
	response.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, messageID, "MessageID"))
	extended := ber.Encode(ber.ClassApplication, ber.TypeConstructed, 24, nil, "Extended Response")
	extended.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagEnumerated, 0, "resultCode"))
	extended.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "", "matchedDN"))
	extended.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "", "diagnosticMessage"))
	response.AppendChild(extended)
	if _, err := conn.Write(response.Bytes()); err != nil {
		return
	}

	tlsConn := tls.Server(conn, config)
	if err := tlsConn.Handshake(); err != nil {
		return
	}
	// Hold the connection open until the client hangs up.
	buf := make([]byte, 1)
	_, _ = tlsConn.Read(buf)
}

// TestStartTLSVerifiesTheDialedHost. go-ldap's StartTLS calls tls.Client with
// the config as given, and tls.Client -- unlike tls.Dial on the ldaps:// path
// -- does not fill in ServerName. Without it every StartTLS handshake failed
// against a real directory, which pushes operators to InsecureSkipVerify or to
// one shared ServerName pinned across every failover host.
func TestStartTLSVerifiesTheDialedHost(t *testing.T) {
	port, pool := startTLSDirectory(t)
	dialer := NewDialer(WithStartTLS(), WithRootCAs(pool))

	conn, err := dialer.DialTLS(context.Background(), net.JoinHostPort("localhost", port))
	if err != nil {
		t.Fatalf("StartTLS to a directory with a valid certificate failed: %v", err)
	}
	_ = conn.Close()
}

// TestStartTLSNameIsPerHost. The name verified is the host actually dialed.
// The same certificate presented for another address must be refused, which
// is what a single ServerName shared across failover hosts would accept.
func TestStartTLSNameIsPerHost(t *testing.T) {
	port, pool := startTLSDirectory(t)
	dialer := NewDialer(WithStartTLS(), WithRootCAs(pool))

	_, err := dialer.DialTLS(context.Background(), net.JoinHostPort("127.0.0.1", port))
	if err == nil {
		t.Fatal("a certificate for localhost was accepted for 127.0.0.1")
	}
	if !strings.Contains(err.Error(), "certificate") {
		t.Errorf("err = %v, want a certificate verification failure", err)
	}

	// The dialer's shared config must not have been pinned by the first dial.
	conn, err := dialer.DialTLS(context.Background(), net.JoinHostPort("localhost", port))
	if err != nil {
		t.Fatalf("a later dial to the right host failed: %v", err)
	}
	_ = conn.Close()
}
