package saml

import (
	"context"
	"encoding/base64"
	"net/url"
	"strings"
	"testing"
)

// FuzzParseRedirectBinding drives the HTTP-Redirect binding decoder.
//
// The input is a query parameter on an unauthenticated endpoint, decoded from
// base64 and then DEFLATE-decompressed. It must never panic and must never
// allocate without bound — a small payload can inflate enormously.
func FuzzParseRedirectBinding(f *testing.F) {
	valid, err := deflateAndEncode([]byte(`<samlp:AuthnRequest ID="_1"/>`))
	if err != nil {
		f.Fatalf("build seed: %v", err)
	}
	f.Add(valid)
	f.Add("")
	f.Add("not-base64!!!")
	f.Add(base64.StdEncoding.EncodeToString([]byte("not deflate data")))
	f.Add(base64.StdEncoding.EncodeToString([]byte{0x00}))
	f.Add(strings.Repeat("A", 10_000))

	f.Fuzz(func(t *testing.T, encoded string) {
		values := url.Values{"SAMLRequest": {encoded}}

		message, err := ParseRedirectBinding(values, "SAMLRequest")
		if err != nil {
			return
		}

		if len(message) > maxDecodedMessageSize {
			t.Fatalf("decoded message is %d bytes, over the %d limit",
				len(message), maxDecodedMessageSize)
		}
	})
}

// FuzzParsePostBinding drives the HTTP-POST binding decoder.
func FuzzParsePostBinding(f *testing.F) {
	f.Add(base64.StdEncoding.EncodeToString([]byte(`<samlp:Response ID="_1"/>`)))
	f.Add("")
	f.Add("!!!")
	f.Add(strings.Repeat("QUFB", 5_000))

	f.Fuzz(func(t *testing.T, encoded string) {
		values := url.Values{"SAMLResponse": {encoded}}

		message, err := ParsePostBinding(values, "SAMLResponse")
		if err != nil {
			return
		}
		if len(message) > maxDecodedMessageSize {
			t.Fatalf("decoded message is %d bytes, over the limit", len(message))
		}
	})
}

// FuzzProcessResponse drives the whole assertion consumer with arbitrary
// input.
//
// This is the most exposed surface in the package: anyone who can reach the
// assertion consumer endpoint controls this input entirely. The invariant is
// absolute — the fuzzer does not hold the identity provider's signing key, so
// nothing it produces may authenticate anyone.
//
// The harness is built once and shared, so the signing key stays fixed across
// iterations. Rebuilding it per iteration would generate a new key each time
// and make the property vacuous: no input could verify, including a genuine
// assertion.
func FuzzProcessResponse(f *testing.F) {
	harness := newAttackHarness(f)

	// A correctly signed response is deliberately excluded from the corpus:
	// every input here must be rejected, so including one that should be
	// accepted would make the invariant untestable.
	f.Add(encode(f, validResponse()))
	f.Add("")
	f.Add("not-base64")
	f.Add(base64.StdEncoding.EncodeToString([]byte("<Response/>")))
	f.Add(base64.StdEncoding.EncodeToString([]byte("<!DOCTYPE x [<!ENTITY e SYSTEM 'file:///etc/passwd'>]><Response>&e;</Response>")))
	f.Add(base64.StdEncoding.EncodeToString([]byte(strings.Repeat("<a>", 1000))))

	// Tamper with a genuinely signed document: the signature no longer covers
	// the modified content, so it must be refused.
	signed := harness.sign(f, validResponse())
	if raw, err := base64.StdEncoding.DecodeString(signed); err == nil {
		tampered := strings.Replace(string(raw), "victim@example.com", "admin@example.com", 1)
		f.Add(base64.StdEncoding.EncodeToString([]byte(tampered)))
	}

	ctx := context.Background()

	f.Fuzz(func(t *testing.T, response string) {
		// A fresh pending request each iteration, since a successful call
		// consumes it.
		harness.newSession(t)

		user, err := harness.sp.ProcessResponse(ctx, response, testSessionID)
		if err != nil {
			return
		}

		t.Fatalf("input authenticated %v without a valid signature from the identity provider", user)
	})
}
