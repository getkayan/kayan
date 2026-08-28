package keys

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"math/big"
	"testing"

	"github.com/golang-jwt/jwt/v5"
)

// roundTrip converts a key to a JWK and back, which is the path a registered
// client's key actually takes.
func roundTrip(t *testing.T, k *Key) any {
	t.Helper()
	jwk, err := KeyToJWK(k)
	if err != nil {
		t.Fatalf("KeyToJWK: %v", err)
	}
	pub, err := jwk.PublicKey()
	if err != nil {
		t.Fatalf("PublicKey: %v", err)
	}
	return pub
}

func TestPublicKeyRoundTripsEveryPublishedKeyType(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa: %v", err)
	}
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("ecdsa: %v", err)
	}
	edPub, edPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519: %v", err)
	}

	t.Run("RSA", func(t *testing.T) {
		pub := roundTrip(t, &Key{KID: "r", Method: jwt.SigningMethodRS256,
			Private: rsaKey, Public: &rsaKey.PublicKey})
		got, ok := pub.(*rsa.PublicKey)
		if !ok {
			t.Fatalf("got %T, want *rsa.PublicKey", pub)
		}
		if !got.Equal(&rsaKey.PublicKey) {
			t.Error("the parsed RSA key is not the one that was published")
		}
	})

	t.Run("EC", func(t *testing.T) {
		pub := roundTrip(t, &Key{KID: "e", Method: jwt.SigningMethodES256,
			Private: ecKey, Public: &ecKey.PublicKey})
		got, ok := pub.(*ecdsa.PublicKey)
		if !ok {
			t.Fatalf("got %T, want *ecdsa.PublicKey", pub)
		}
		if !got.Equal(&ecKey.PublicKey) {
			t.Error("the parsed EC key is not the one that was published")
		}
	})

	t.Run("Ed25519", func(t *testing.T) {
		pub := roundTrip(t, &Key{KID: "o", Method: jwt.SigningMethodEdDSA,
			Private: edPriv, Public: edPub})
		got, ok := pub.(ed25519.PublicKey)
		if !ok {
			t.Fatalf("got %T, want ed25519.PublicKey", pub)
		}
		if !got.Equal(edPub) {
			t.Error("the parsed Ed25519 key is not the one that was published")
		}
	})
}

// TestSymmetricJWKIsRefused covers algorithm confusion.
//
// An "oct" key carries a shared secret. Returning it where a public key was
// expected hands the verifier a HMAC secret, which is the setup for a token
// signed HS256 over a published RSA modulus being accepted as RS256.
func TestSymmetricJWKIsRefused(t *testing.T) {
	jwk := JWK{Kty: "oct", Kid: "shared", Alg: "HS256",
		X: base64.RawURLEncoding.EncodeToString([]byte("secret"))}

	pub, err := jwk.PublicKey()
	if !errors.Is(err, ErrSymmetricJWK) {
		t.Errorf("error = %v, want ErrSymmetricJWK", err)
	}
	if pub != nil {
		t.Error("a symmetric key was returned as a public key")
	}
}

// TestShortRSAModulusIsRefused. A 512-bit modulus is factorable on a laptop,
// so accepting one turns signature verification into a formality that any
// caller registering their own JWKS can opt out of.
func TestShortRSAModulusIsRefused(t *testing.T) {
	small, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatalf("rsa: %v", err)
	}
	jwk := JWK{
		Kty: "RSA", Kid: "small",
		N: base64.RawURLEncoding.EncodeToString(small.N.Bytes()),
		E: base64.RawURLEncoding.EncodeToString(big.NewInt(int64(small.E)).Bytes()),
	}

	if _, err := jwk.PublicKey(); !errors.Is(err, ErrMalformedJWK) {
		t.Errorf("error = %v, want a 1024-bit modulus to be refused", err)
	}
}

// TestOffCurvePointIsRefused covers invalid-curve attacks. A point that is not
// on the named curve makes the group arithmetic leak information about
// whatever private scalar is used with it.
func TestOffCurvePointIsRefused(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("ecdsa: %v", err)
	}
	// Move Y off the curve while keeping the encoding well formed.
	bogus := new(big.Int).Add(key.Y, big.NewInt(1))
	pad := func(v *big.Int) string {
		buf := make([]byte, 32)
		v.FillBytes(buf)
		return base64.RawURLEncoding.EncodeToString(buf)
	}
	jwk := JWK{Kty: "EC", Crv: "P-256", Kid: "bent", X: pad(key.X), Y: pad(bogus)}

	pub, err := jwk.PublicKey()
	if !errors.Is(err, ErrMalformedJWK) {
		t.Errorf("error = %v, want an off-curve point to be refused", err)
	}
	if pub != nil {
		t.Error("an off-curve point was returned as a public key")
	}
}

// TestShortECCoordinateIsRefused. RFC 7518 section 6.2.1.2 fixes the octet
// length at the field size. A short encoding of the same key would produce a
// different thumbprint, so two registrations of one key would not compare
// equal.
func TestShortECCoordinateIsRefused(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("ecdsa: %v", err)
	}
	jwk := JWK{Kty: "EC", Crv: "P-256",
		X: base64.RawURLEncoding.EncodeToString(key.X.Bytes()[:16]),
		Y: base64.RawURLEncoding.EncodeToString(key.Y.FillBytes(make([]byte, 32))),
	}

	if _, err := jwk.PublicKey(); !errors.Is(err, ErrMalformedJWK) {
		t.Errorf("error = %v, want a short coordinate to be refused", err)
	}
}

// TestFindRefusesToGuessWhenKidIsAbsent. Picking "the first key" for a token
// with no kid is how a signature made with a retired key keeps verifying
// after a rotation.
func TestFindRefusesToGuessWhenKidIsAbsent(t *testing.T) {
	set := JWKS{Keys: []JWK{{Kid: "one", Kty: "RSA"}, {Kid: "two", Kty: "RSA"}}}

	if _, ok := set.Find(""); ok {
		t.Error("an empty kid selected a key out of a set of two")
	}
	if _, ok := set.Find("three"); ok {
		t.Error("an unregistered kid matched")
	}
	got, ok := set.Find("two")
	if !ok || got.Kid != "two" {
		t.Errorf("Find(two) = %v, %v", got.Kid, ok)
	}

	// A single-key set has no ambiguity to resolve, so a kid-less lookup is
	// safe there and is what most registrations look like.
	single := JWKS{Keys: []JWK{{Kid: "only", Kty: "RSA"}}}
	if _, ok := single.Find(""); !ok {
		t.Error("a single-key set did not resolve a kid-less lookup")
	}
}

func TestParseJWKSRejectsGarbage(t *testing.T) {
	if _, err := ParseJWKS([]byte("not json")); !errors.Is(err, ErrMalformedJWK) {
		t.Errorf("error = %v, want ErrMalformedJWK", err)
	}

	// A well-formed set must survive the round trip through JSON.
	raw, err := json.Marshal(JWKS{Keys: []JWK{{Kty: "RSA", Kid: "k"}}})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	set, err := ParseJWKS(raw)
	if err != nil {
		t.Fatalf("ParseJWKS: %v", err)
	}
	if len(set.Keys) != 1 || set.Keys[0].Kid != "k" {
		t.Errorf("ParseJWKS = %+v", set)
	}
}
