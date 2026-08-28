package oidc

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
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

// TestPARIsNotAdvertisedWithoutSupport.
//
// A client that reads pushed_authorization_request_endpoint from discovery
// starts pushing to it. If the provider does not serve one, that is a 404
// halfway through a flow the client cannot restart -- and this package has
// shipped exactly this mistake before, six times.
func TestPARIsNotAdvertisedWithoutSupport(t *testing.T) {
	server := discoveryServer(t)

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
	if doc.PushedAuthorizationRequestEndpoint != "" {
		t.Errorf("advertised %q with no provider able to serve it",
			doc.PushedAuthorizationRequestEndpoint)
	}
	if doc.RequirePushedAuthorizationRequests {
		t.Error("advertised require_pushed_authorization_requests with no endpoint; " +
			"a client reading that refuses to send any authorization request it can complete")
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
