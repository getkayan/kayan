package saml

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"
)

// testKeyPair generates a self-signed certificate for tests.
//
// Keys are generated per test rather than checked in, so a fixture can never
// become a real credential someone reuses.
func testKeyPair(t *testing.T) (*rsa.PrivateKey, *x509.Certificate) {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "kayan-saml-test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse certificate: %v", err)
	}
	return key, cert
}

// testSigner returns a signer and the certificate that verifies it.
func testSigner(t *testing.T) (Signer, *x509.Certificate) {
	t.Helper()

	key, cert := testKeyPair(t)
	signer, err := NewXMLDSigSigner(key, cert)
	if err != nil {
		t.Fatalf("build signer: %v", err)
	}
	return signer, cert
}
