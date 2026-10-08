package flow

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"testing"
	"time"

	"github.com/go-webauthn/webauthn/webauthn"
)

type testCA struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
}

func newTestCA(t *testing.T, name string) *testCA {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: name},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign,
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
	return &testCA{cert: cert, key: key}
}

// leaf issues an attestation certificate shaped like a real one: no TLS key
// usage, OU=Authenticator Attestation.
func (ca *testCA) leaf(t *testing.T, notAfter time.Time) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject: pkix.Name{
			CommonName:         "Attestation",
			OrganizationalUnit: []string{"Authenticator Attestation"},
		},
		NotBefore: time.Now().Add(-time.Hour),
		NotAfter:  notAfter,
		KeyUsage:  x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, ca.cert, &key.PublicKey, ca.key)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

func statementWith(certs ...[]byte) map[string]any {
	x5c := make([]any, len(certs))
	for i, c := range certs {
		x5c[i] = c
	}
	return map[string]any{"alg": int64(-7), "sig": []byte("sig"), "x5c": x5c}
}

// rootsFor returns ca's root for aaguid only.
func rootsFor(aaguid []byte, ca *testCA) AttestationRoots {
	return AttestationRootsFunc(func(_ context.Context, got []byte) ([]*x509.Certificate, error) {
		if string(got) == string(aaguid) {
			return []*x509.Certificate{ca.cert}, nil
		}
		return nil, nil
	})
}

// judged runs the strategy's policy hook and returns what the policy saw.
func judged(t *testing.T, roots AttestationRoots, aaguid []byte, statement map[string]any) (AttestationInfo, error) {
	t.Helper()
	strategy := passkeyStrategy(t, WebAuthnHooks{})
	strategy.config.AttestationRoots = roots

	var seen AttestationInfo
	strategy.config.AttestationPolicy = AttestationPolicyFunc(func(_ context.Context, info AttestationInfo) error {
		seen = info
		return RequireTrustedAttestation().AllowAuthenticator(context.Background(), info)
	})
	err := strategy.applyAttestationPolicy(context.Background(), &webauthn.Credential{
		ID:              []byte("credential-1"),
		AttestationType: "packed",
		Authenticator:   webauthn.Authenticator{AAGUID: aaguid},
	}, statement)
	return seen, err
}

func TestChainToTheModelsRootIsTrusted(t *testing.T) {
	vendor := newTestCA(t, "vendor root")
	info, err := judged(t, rootsFor(yubikeyAAGUID, vendor), yubikeyAAGUID,
		statementWith(vendor.leaf(t, time.Now().Add(time.Hour))))
	if err != nil {
		t.Fatalf("a chain to the model's root was refused: %v", err)
	}
	if !info.ChainVerified || len(info.TrustPath) != 1 {
		t.Errorf("ChainVerified=%v TrustPath=%d", info.ChainVerified, len(info.TrustPath))
	}
}

// TestSelfMintedCAIsNotTrusted is the attack: a software authenticator mints
// its own CA, issues a leaf that looks like a manufacturer's, and claims a
// listed AAGUID. The statement signature verifies against the leaf; only the
// chain says it came from nobody.
func TestSelfMintedCAIsNotTrusted(t *testing.T) {
	vendor := newTestCA(t, "vendor root")
	attacker := newTestCA(t, "vendor root")

	info, err := judged(t, rootsFor(yubikeyAAGUID, vendor), yubikeyAAGUID,
		statementWith(attacker.leaf(t, time.Now().Add(time.Hour))))
	if !errors.Is(err, ErrAttestationMissing) {
		t.Fatalf("err = %v, want ErrAttestationMissing", err)
	}
	if info.ChainVerified {
		t.Error("a self-minted chain was reported verified")
	}
}

// TestRootsAreScopedToTheirModel. A root trusted for one model must not vouch
// for another model's AAGUID.
func TestRootsAreScopedToTheirModel(t *testing.T) {
	vendor := newTestCA(t, "vendor root")
	_, err := judged(t, rootsFor(unknownAAGUID, vendor), yubikeyAAGUID,
		statementWith(vendor.leaf(t, time.Now().Add(time.Hour))))
	if !errors.Is(err, ErrAttestationMissing) {
		t.Fatalf("err = %v, want ErrAttestationMissing", err)
	}
}

func TestNoRootsConfiguredTrustsNothing(t *testing.T) {
	vendor := newTestCA(t, "vendor root")
	_, err := judged(t, nil, yubikeyAAGUID, statementWith(vendor.leaf(t, time.Now().Add(time.Hour))))
	if !errors.Is(err, ErrAttestationMissing) {
		t.Fatalf("err = %v, want ErrAttestationMissing", err)
	}
}

// TestSelfAttestationIsNotTrusted. Packed self attestation carries no x5c and
// arrives with the same format string as a manufacturer-signed statement.
func TestSelfAttestationIsNotTrusted(t *testing.T) {
	vendor := newTestCA(t, "vendor root")
	_, err := judged(t, rootsFor(yubikeyAAGUID, vendor), yubikeyAAGUID,
		map[string]any{"alg": int64(-7), "sig": []byte("sig")})
	if !errors.Is(err, ErrAttestationMissing) {
		t.Fatalf("err = %v, want ErrAttestationMissing", err)
	}
}

func TestExpiredAttestationCertificateIsNotTrusted(t *testing.T) {
	vendor := newTestCA(t, "vendor root")
	_, err := judged(t, rootsFor(yubikeyAAGUID, vendor), yubikeyAAGUID,
		statementWith(vendor.leaf(t, time.Now().Add(-time.Minute))))
	if !errors.Is(err, ErrAttestationMissing) {
		t.Fatalf("err = %v, want ErrAttestationMissing", err)
	}
}

func TestZeroAAGUIDIsNeverChainVerified(t *testing.T) {
	vendor := newTestCA(t, "vendor root")
	_, err := judged(t, rootsFor(zeroAAGUID, vendor), zeroAAGUID,
		statementWith(vendor.leaf(t, time.Now().Add(time.Hour))))
	if !errors.Is(err, ErrAttestationMissing) {
		t.Fatalf("err = %v, want ErrAttestationMissing", err)
	}
}

// TestRootsSourceFailureIsReported. A source that cannot answer is not a "no"
// to be judged, and must never become a "yes".
func TestRootsSourceFailureIsReported(t *testing.T) {
	vendor := newTestCA(t, "vendor root")
	outage := errors.New("metadata unavailable")
	roots := AttestationRootsFunc(func(context.Context, []byte) ([]*x509.Certificate, error) {
		return nil, outage
	})
	_, err := judged(t, roots, yubikeyAAGUID, statementWith(vendor.leaf(t, time.Now().Add(time.Hour))))
	if !errors.Is(err, outage) {
		t.Fatalf("err = %v, want the roots source's error", err)
	}
}

func TestMalformedTrustPathIsRefused(t *testing.T) {
	vendor := newTestCA(t, "vendor root")
	_, err := judged(t, rootsFor(yubikeyAAGUID, vendor), yubikeyAAGUID,
		map[string]any{"x5c": []any{[]byte("not a certificate")}})
	if !errors.Is(err, ErrAttestationMissing) {
		t.Fatalf("err = %v, want ErrAttestationMissing", err)
	}
}
