package oauth2

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"testing"
)

// TestLoopbackRedirectAcceptsAnyPort is RFC 8252 section 7.3: a native app
// listens on whatever port the operating system gives it.
func TestLoopbackRedirectAcceptsAnyPort(t *testing.T) {
	client := &Client{RedirectURIs: []string{
		"http://127.0.0.1/callback",
		"http://[::1]:8080/cb?app=cli",
	}}
	for _, uri := range []string{
		"http://127.0.0.1/callback",
		"http://127.0.0.1:51234/callback",
		"http://127.0.0.1:1/callback",
		"http://127.0.0.1:65535/callback",
		"http://[::1]/cb?app=cli",
		"http://[::1]:49152/cb?app=cli",
	} {
		if !client.AllowsRedirectURI(uri) {
			t.Errorf("%s was refused", uri)
		}
	}
}

// TestLoopbackRedirectChangesOnlyThePort is the adversarial corpus. Each entry
// differs from a registered loopback URI in something other than the port.
func TestLoopbackRedirectChangesOnlyThePort(t *testing.T) {
	client := &Client{RedirectURIs: []string{"http://127.0.0.1/callback", "http://[::1]/cb"}}
	for _, uri := range []string{
		"http://127.0.0.1.attacker.test/callback",
		"http://127.0.0.1.attacker.test:8080/callback",
		"http://127.0.0.10/callback",
		"http://127.0.0.1@attacker.test/callback",
		"http://127.0.0.1:8080@attacker.test/callback",
		"http://127.0.0.2:8080/callback",
		"http://127.1:8080/callback",
		"http://0x7f.0.0.1:8080/callback",
		"http://[::ffff:127.0.0.1]:8080/callback",
		"http://localhost:8080/callback",
		"https://127.0.0.1:8080/callback",
		"HTTP://127.0.0.1:8080/callback",
		"http://127.0.0.1:8080/callback/",
		"http://127.0.0.1:8080/Callback",
		"http://127.0.0.1:8080/callback/../callback",
		"http://127.0.0.1:8080/%63allback",
		"http://127.0.0.1:8080/callback?x=1",
		"http://127.0.0.1:8080/callback#frag",
		`http://127.0.0.1:8080\@attacker.test/callback`,
		`http://127.0.0.1:8080/callback\`,
		"http://127.0.0.1:/callback",
		"http://127.0.0.1:0/callback",
		"http://127.0.0.1:65536/callback",
		"http://127.0.0.1:123456/callback",
		"http://127.0.0.1:80a/callback",
		"http://[::1]:8080/callback",
		"http://127.0.0.1:8080/cb",
	} {
		if client.AllowsRedirectURI(uri) {
			t.Errorf("%s was accepted", uri)
		}
	}
}

// TestLocalhostGetsNoPortException. localhost resolves through the hosts file
// and DNS; RFC 8252 section 8.3 recommends against it, and it keeps exact
// matching.
func TestLocalhostGetsNoPortException(t *testing.T) {
	client := &Client{RedirectURIs: []string{"http://localhost:8080/callback"}}
	if !client.AllowsRedirectURI("http://localhost:8080/callback") {
		t.Error("the registered URI itself was refused")
	}
	if client.AllowsRedirectURI("http://localhost:9090/callback") {
		t.Error("localhost was given the loopback port exception")
	}
}

// TestNonLoopbackRedirectStaysExact. The exception must not widen matching
// for ordinary registrations.
func TestNonLoopbackRedirectStaysExact(t *testing.T) {
	client := &Client{RedirectURIs: []string{"https://app.example.com/callback"}}
	if client.AllowsRedirectURI("https://app.example.com:8443/callback") {
		t.Error("a port change was accepted on a non-loopback URI")
	}
}

// TestLoopbackCodeIsBoundToItsPort. The code is issued for one port and must
// be redeemed with that exact URI: another local process listening on a
// different port must not redeem it.
func TestLoopbackCodeIsBoundToItsPort(t *testing.T) {
	ctx := context.Background()
	store := newTestOAuth2Store()
	client := testClient(t, "top-secret", "http://127.0.0.1/callback")
	store.clients["client-1"] = client

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	provider := NewProvider(store, store, store, "https://issuer.example.com", key, "kid-1",
		WithProviderAudit(store, func(context.Context, error) {}))

	verifier := "verifier-value"
	issued := "http://127.0.0.1:51234/callback"
	code, err := provider.GenerateAuthCode(ctx, "client-1", "user-1", issued, []string{"openid"}, providerChallenge(verifier), "S256")
	if err != nil {
		t.Fatalf("a loopback redirect with a runtime port was refused: %v", err)
	}

	if _, err := provider.Exchange(ctx, code, "client-1", "top-secret", "http://127.0.0.1:51235/callback", verifier); !errors.Is(err, ErrInvalidGrant) {
		t.Fatalf("redeemed with another port: err = %v, want invalid_grant", err)
	}
}

// TestMalformedRegistrationGetsNoPortException. The exception applies only to
// a registration that really is a loopback literal. One that merely starts
// with the literal, or carries a fragment, keeps exact matching -- otherwise
// splicing a port into it yields strings that are not the registered URI.
func TestMalformedRegistrationGetsNoPortException(t *testing.T) {
	for registered, request := range map[string]string{
		"http://127.0.0.1.example.test/cb": "http://127.0.0.1:8080.example.test/cb",
		"http://127.0.0.1/cb#fragment":     "http://127.0.0.1:8080/cb#fragment",
	} {
		client := &Client{RedirectURIs: []string{registered}}
		if client.AllowsRedirectURI(request) {
			t.Errorf("registered %q: %q was accepted", registered, request)
		}
	}
}
