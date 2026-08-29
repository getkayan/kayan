package saml

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"
)

type metadataDoerFunc func(*http.Request) (*http.Response, error)

func (f metadataDoerFunc) Do(req *http.Request) (*http.Response, error) { return f(req) }

func TestMetadataURLPolicyRejectsLocalTargets(t *testing.T) {
	for _, raw := range []string{
		"http://idp.example.test/metadata",
		"https://localhost/metadata",
		"https://127.0.0.1/metadata",
		"https://10.0.0.1/metadata",
		"https://user:pass@idp.example.test/metadata",
	} {
		t.Run(raw, func(t *testing.T) {
			sp := NewServiceProvider(Config{}, nil, nil, nil, WithMetadataHTTPClient(metadataDoerFunc(
				func(*http.Request) (*http.Response, error) {
					t.Fatal("HTTP client called for a refused URL")
					return nil, nil
				},
			)))
			if err := sp.RegisterIdPFromMetadata(context.Background(), "idp", raw); err == nil {
				t.Fatal("expected URL policy error")
			}
		})
	}
}

// markerKey is a named type so the context value cannot collide with an
// anonymous struct key used anywhere else.
type markerKey struct{}

func TestMetadataFetchUsesInjectedClientAndContext(t *testing.T) {
	const metadata = `<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" entityID="https://idp.example.test"><IDPSSODescriptor><SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://idp.example.test/sso"/></IDPSSODescriptor></EntityDescriptor>`
	ctx := context.WithValue(context.Background(), markerKey{}, "marker")
	sp := NewServiceProvider(Config{}, nil, nil, nil, WithMetadataHTTPClient(metadataDoerFunc(
		func(req *http.Request) (*http.Response, error) {
			if req.Context() != ctx {
				t.Fatal("request did not retain caller context")
			}
			return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(metadata))}, nil
		},
	)))
	if err := sp.RegisterIdPFromMetadata(ctx, "idp", "https://idp.example.test/metadata"); err != nil {
		t.Fatalf("RegisterIdPFromMetadata: %v", err)
	}
	if idp, ok := sp.GetIdP("idp"); !ok || idp.SSOUrl != "https://idp.example.test/sso" {
		t.Fatalf("registered IdP = %+v, %v", idp, ok)
	}
}

func TestMetadataFetchRejectsOversizedResponse(t *testing.T) {
	sp := NewServiceProvider(Config{}, nil, nil, nil, WithMetadataHTTPClient(metadataDoerFunc(
		func(*http.Request) (*http.Response, error) {
			body := io.LimitReader(strings.NewReader(strings.Repeat("x", 1024)), maxMetadataBytes+1)
			return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(io.MultiReader(
				strings.NewReader(strings.Repeat("x", maxMetadataBytes)), body,
			))}, nil
		},
	)))
	if err := sp.RegisterIdPFromMetadata(context.Background(), "idp", "https://idp.example.test/metadata"); err == nil {
		t.Fatal("expected oversized metadata error")
	}
}
