package keys

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"testing"

	"github.com/golang-jwt/jwt/v5"
)

// TestKeyToJWKRoundTrip proves each supported key type survives conversion to
// a JWK and back to a usable public key.
func TestKeyToJWKRoundTrip(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate RSA key: %v", err)
	}
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate ECDSA key: %v", err)
	}
	edPub, edPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate Ed25519 key: %v", err)
	}

	tests := []struct {
		name    string
		key     *Key
		wantKty string
		wantCrv string
		verify  func(t *testing.T, jwk JWK)
	}{
		{
			name:    "RSA",
			key:     &Key{KID: "rsa-1", Method: jwt.SigningMethodRS256, Private: rsaKey, Public: &rsaKey.PublicKey},
			wantKty: "RSA",
			verify: func(t *testing.T, jwk JWK) {
				n, err := base64.RawURLEncoding.DecodeString(jwk.N)
				if err != nil {
					t.Fatalf("decode n: %v", err)
				}
				if new(big.Int).SetBytes(n).Cmp(rsaKey.PublicKey.N) != 0 {
					t.Error("modulus does not round-trip")
				}
				e, err := base64.RawURLEncoding.DecodeString(jwk.E)
				if err != nil {
					t.Fatalf("decode e: %v", err)
				}
				if int(new(big.Int).SetBytes(e).Int64()) != rsaKey.PublicKey.E {
					t.Error("exponent does not round-trip")
				}
			},
		},
		{
			name:    "ECDSA P-256",
			key:     &Key{KID: "ec-1", Method: jwt.SigningMethodES256, Private: ecKey, Public: &ecKey.PublicKey},
			wantKty: "EC",
			wantCrv: "P-256",
			verify: func(t *testing.T, jwk JWK) {
				x, err := base64.RawURLEncoding.DecodeString(jwk.X)
				if err != nil {
					t.Fatalf("decode x: %v", err)
				}
				y, err := base64.RawURLEncoding.DecodeString(jwk.Y)
				if err != nil {
					t.Fatalf("decode y: %v", err)
				}
				// RFC 7518 section 6.2.1.2: coordinates are fixed-width.
				if len(x) != 32 || len(y) != 32 {
					t.Errorf("coordinate sizes = (%d, %d), want (32, 32)", len(x), len(y))
				}
				if new(big.Int).SetBytes(x).Cmp(ecKey.X) != 0 {
					t.Error("x does not round-trip")
				}
				if new(big.Int).SetBytes(y).Cmp(ecKey.Y) != 0 {
					t.Error("y does not round-trip")
				}
			},
		},
		{
			name:    "Ed25519",
			key:     &Key{KID: "ed-1", Method: jwt.SigningMethodEdDSA, Private: edPriv, Public: edPub},
			wantKty: "OKP",
			wantCrv: "Ed25519",
			verify: func(t *testing.T, jwk JWK) {
				x, err := base64.RawURLEncoding.DecodeString(jwk.X)
				if err != nil {
					t.Fatalf("decode x: %v", err)
				}
				if string(x) != string(edPub) {
					t.Error("public key does not round-trip")
				}
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			jwk, err := KeyToJWK(tc.key)
			if err != nil {
				t.Fatalf("KeyToJWK: %v", err)
			}
			if jwk.Kty != tc.wantKty {
				t.Errorf("kty = %q, want %q", jwk.Kty, tc.wantKty)
			}
			if tc.wantCrv != "" && jwk.Crv != tc.wantCrv {
				t.Errorf("crv = %q, want %q", jwk.Crv, tc.wantCrv)
			}
			if jwk.Kid != tc.key.KID {
				t.Errorf("kid = %q, want %q", jwk.Kid, tc.key.KID)
			}
			if jwk.Alg != tc.key.Algorithm() {
				t.Errorf("alg = %q, want %q", jwk.Alg, tc.key.Algorithm())
			}
			if jwk.Use != UseSignature {
				t.Errorf("use = %q, want %q", jwk.Use, UseSignature)
			}
			tc.verify(t, jwk)
		})
	}
}

// TestKeyToJWKAlgorithmIsNotHardcoded guards the bug this package replaced,
// where every JWK was emitted with alg "RS256" regardless of the actual key.
func TestKeyToJWKAlgorithmIsNotHardcoded(t *testing.T) {
	ecKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	key := &Key{KID: "ec-384", Method: jwt.SigningMethodES384, Private: ecKey, Public: &ecKey.PublicKey}

	jwk, err := KeyToJWK(key)
	if err != nil {
		t.Fatalf("KeyToJWK: %v", err)
	}
	if jwk.Alg != "ES384" {
		t.Errorf("alg = %q, want ES384", jwk.Alg)
	}
	if jwk.Crv != "P-384" {
		t.Errorf("crv = %q, want P-384", jwk.Crv)
	}
}

// TestJWKSExcludesSymmetricKeys proves an HMAC secret is never published.
func TestJWKSExcludesSymmetricKeys(t *testing.T) {
	ctx := context.Background()

	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	secret := []byte("super-secret-hmac-key")

	provider := NewStaticProvider(
		&Key{KID: "rsa-1", Method: jwt.SigningMethodRS256, Private: rsaKey, Public: &rsaKey.PublicKey},
		&Key{KID: "hmac-1", Method: jwt.SigningMethodHS256, Private: secret},
	)

	jwks, err := BuildJWKS(ctx, provider)
	if err != nil {
		t.Fatalf("BuildJWKS: %v", err)
	}
	if len(jwks.Keys) != 1 {
		t.Fatalf("JWKS has %d keys, want 1 (the symmetric key must be excluded)", len(jwks.Keys))
	}
	if jwks.Keys[0].Kid != "rsa-1" {
		t.Errorf("published kid = %q, want rsa-1", jwks.Keys[0].Kid)
	}

	// Belt and braces: the secret must not appear anywhere in the serialized set.
	encoded, err := json.Marshal(jwks)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if b64 := base64.RawURLEncoding.EncodeToString(secret); containsSubstring(string(encoded), b64) {
		t.Fatal("symmetric key material leaked into JWKS")
	}
	if containsSubstring(string(encoded), string(secret)) {
		t.Fatal("symmetric key material leaked into JWKS")
	}
}

// TestJWKSOmitsEmptyMembers proves an RSA key does not carry empty EC members
// and vice versa, which some strict verifiers reject.
func TestJWKSOmitsEmptyMembers(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	jwk, err := KeyToJWK(&Key{KID: "rsa-1", Method: jwt.SigningMethodRS256, Private: rsaKey, Public: &rsaKey.PublicKey})
	if err != nil {
		t.Fatalf("KeyToJWK: %v", err)
	}

	encoded, err := json.Marshal(jwk)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var decoded map[string]any
	if err := json.Unmarshal(encoded, &decoded); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	for _, member := range []string{"crv", "x", "y"} {
		if _, present := decoded[member]; present {
			t.Errorf("RSA JWK carries EC member %q", member)
		}
	}
	for _, member := range []string{"n", "e", "kty", "kid", "alg", "use"} {
		if _, present := decoded[member]; !present {
			t.Errorf("RSA JWK is missing member %q", member)
		}
	}
}

func TestBuildJWKSNilProvider(t *testing.T) {
	if _, err := BuildJWKS(context.Background(), nil); err == nil {
		t.Fatal("nil provider accepted")
	}
}

func containsSubstring(haystack, needle string) bool {
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
