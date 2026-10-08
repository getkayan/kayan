package oidc

import (
	"context"
	"testing"

	"github.com/getkayan/kayan/kayan-oidc-provider/oauth2"
)

type deviceSupport bool

func (d deviceSupport) SupportsDeviceAuthorization() bool { return bool(d) }

const deviceEndpoint = "https://issuer.example.test/device"

func baseEndpoints() Endpoints {
	return Endpoints{
		Authorization: "https://issuer.example.test/authorize",
		Token:         "https://issuer.example.test/token",
	}
}

func TestDeviceGrantIsAdvertisedWhenServed(t *testing.T) {
	server := discoveryServer(t, WithDeviceAuthorizationSupport(deviceSupport(true)))
	endpoints := baseEndpoints()
	endpoints.DeviceAuthorization = deviceEndpoint

	doc, err := server.BuildDiscovery(context.Background(), DiscoveryOptions{Endpoints: endpoints})
	if err != nil {
		t.Fatalf("BuildDiscovery: %v", err)
	}
	if doc.DeviceAuthorizationEndpoint != deviceEndpoint {
		t.Errorf("endpoint = %q", doc.DeviceAuthorizationEndpoint)
	}
	if !contains(doc.GrantTypesSupported, oauth2.GrantDeviceCode) {
		t.Errorf("grant types = %v, want the device grant", doc.GrantTypesSupported)
	}
}

// TestDeviceGrantIsNeverAdvertisedUnserved. A client that reads the device
// grant from metadata and finds the provider refusing it fails at the first
// poll, inside the client, where nobody can diagnose it.
func TestDeviceGrantIsNeverAdvertisedUnserved(t *testing.T) {
	for name, tc := range map[string]struct {
		opts     []ServerOption
		endpoint string
		grants   []string
	}{
		"endpoint, no provider":       {endpoint: deviceEndpoint},
		"endpoint, provider disabled": {opts: []ServerOption{WithDeviceAuthorizationSupport(deviceSupport(false))}, endpoint: deviceEndpoint},
		"grant listed, no provider":   {grants: []string{oauth2.GrantAuthorizationCode, oauth2.GrantDeviceCode}},
		"served, but no endpoint set": {opts: []ServerOption{WithDeviceAuthorizationSupport(deviceSupport(true))}},
	} {
		t.Run(name, func(t *testing.T) {
			server := discoveryServer(t, tc.opts...)
			endpoints := baseEndpoints()
			endpoints.DeviceAuthorization = tc.endpoint
			if _, err := server.BuildDiscovery(context.Background(), DiscoveryOptions{Endpoints: endpoints, GrantTypes: tc.grants}); err == nil {
				t.Fatal("BuildDiscovery accepted an inconsistent device grant configuration")
			}
		})
	}
}

func TestNoDeviceGrantByDefault(t *testing.T) {
	doc, err := discoveryServer(t).BuildDiscovery(context.Background(), DiscoveryOptions{Endpoints: baseEndpoints()})
	if err != nil {
		t.Fatal(err)
	}
	if doc.DeviceAuthorizationEndpoint != "" || contains(doc.GrantTypesSupported, oauth2.GrantDeviceCode) {
		t.Error("the device grant was advertised without being configured")
	}
}

// TestProviderSatisfiesDeviceAuthorizationSource keeps the wiring compiling.
var _ DeviceAuthorizationSource = (*oauth2.Provider)(nil)

func contains(list []string, value string) bool {
	for _, v := range list {
		if v == value {
			return true
		}
	}
	return false
}
