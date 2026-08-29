package oidc

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"strings"
	"testing"

	"github.com/getkayan/kayan/core/keys"
	"github.com/golang-jwt/jwt/v5"
)

// discoveryServer builds a server with signing keys, which BuildDiscovery
// needs to advertise its algorithms.
func discoveryServer(t *testing.T, opts ...ServerOption) *Server {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	provider := keys.NewStaticProvider(&keys.Key{
		KID: "kid-1", Method: jwt.SigningMethodRS256,
		Private: key, Public: &key.PublicKey,
	})
	opts = append([]ServerOption{WithServerKeyProvider(provider)}, opts...)
	return NewServer("https://issuer.example.test", nil, "", opts...)
}

// TestPAREndpointWithoutAProviderIsRefused.
//
// A relying party configures itself from this document. Advertising an
// endpoint the provider cannot serve strands it mid-flow; silently omitting an
// endpoint the provider does serve leaves every client configured without PAR,
// so a deployment that believes it requires PAR quietly does not.
//
// Both are misconfigurations, so BuildDiscovery reports them rather than
// picking one and continuing -- the same treatment the end-session endpoint
// already gets.
func TestPAREndpointWithoutAProviderIsRefused(t *testing.T) {
	server := discoveryServer(t)

	_, err := server.BuildDiscovery(context.Background(), DiscoveryOptions{
		Endpoints: Endpoints{
			Authorization:              "https://issuer.example.test/authorize",
			Token:                      "https://issuer.example.test/token",
			PushedAuthorizationRequest: "https://issuer.example.test/par",
		},
	})
	if err == nil {
		t.Fatal("a PAR endpoint was advertised with no provider able to serve it")
	}
	if !strings.Contains(err.Error(), "WithPushedRequestSupport") {
		t.Errorf("error = %v, want it to name the missing option", err)
	}
}

// TestNoPAREndpointIsFine keeps the check scoped: a deployment that does not
// serve PAR must still be able to build a discovery document.
func TestNoPAREndpointIsFine(t *testing.T) {
	server := discoveryServer(t)

	doc, err := server.BuildDiscovery(context.Background(), DiscoveryOptions{
		Endpoints: Endpoints{
			Authorization: "https://issuer.example.test/authorize",
			Token:         "https://issuer.example.test/token",
		},
	})
	if err != nil {
		t.Fatalf("BuildDiscovery: %v", err)
	}
	if doc.PushedAuthorizationRequestEndpoint != "" {
		t.Error("PAR was advertised without an endpoint")
	}
}

// TestPARIsAdvertisedWhenServed keeps the check above from being a blanket
// omission, which would leave PAR undiscoverable for deployments that do
// serve it.
func TestPARIsAdvertisedWhenServed(t *testing.T) {
	server := discoveryServer(t, WithPushedRequestSupport(servedPAR{required: true}))

	doc, err := server.BuildDiscovery(context.Background(), DiscoveryOptions{
		Endpoints: Endpoints{
			Authorization:              "https://issuer.example.test/authorize",
			Token:                      "https://issuer.example.test/token",
			PushedAuthorizationRequest: "https://issuer.example.test/par",
		},
	})
	if err != nil {
		t.Fatalf("BuildDiscovery: %v", err)
	}
	if doc.PushedAuthorizationRequestEndpoint != "https://issuer.example.test/par" {
		t.Errorf("endpoint = %q, want it advertised", doc.PushedAuthorizationRequestEndpoint)
	}
	if !doc.RequirePushedAuthorizationRequests {
		t.Error("the provider requires PAR but discovery does not say so, so clients " +
			"send plain authorization requests it will refuse")
	}
}

// servedPAR reports a provider that serves pushed authorization requests.
type servedPAR struct{ required bool }

func (p servedPAR) SupportsPushedRequests() bool { return true }
func (p servedPAR) RequiresPushedRequests() bool { return p.required }
