package saml

import (
	"context"
	"encoding/base64"
	"encoding/xml"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestNewIdentityProvider(t *testing.T) {
	config := IdPServerConfig{
		EntityID: "http://idp.example.com",
		SSOUrl:   "http://idp.example.com/sso",
	}
	repo := newMockIdentityRepo()
	store := newMockSessionStore()

	idp := NewIdentityProvider(config, repo, store)
	if idp == nil {
		t.Fatal("NewIdentityProvider returned nil")
	}
}

func TestRegisterSP(t *testing.T) {
	config := IdPServerConfig{
		EntityID: "http://idp.example.com",
	}
	idp := NewIdentityProvider(config, nil, nil)

	sp := &SPRegistration{
		ID:       "sp1",
		EntityID: "http://sp.example.com",
		ACSUrl:   "http://sp.example.com/acs",
	}

	idp.RegisterSP(sp)

	retrieved, err := idp.GetSP("sp1")
	if err != nil {
		t.Errorf("Failed to retrieve SP by ID: %v", err)
	}
	if retrieved != sp {
		t.Error("Retrieved SP does not match registered SP")
	}

	retrievedByEntity, err := idp.GetSP("http://sp.example.com")
	if err != nil {
		t.Errorf("Failed to retrieve SP by EntityID: %v", err)
	}
	if retrievedByEntity != sp {
		t.Error("Retrieved SP by EntityID does not match")
	}
}

func TestHandleSSORequest_ValidPOST(t *testing.T) {
	config := IdPServerConfig{
		EntityID: "http://idp.example.com",
	}
	idp := NewIdentityProvider(config, nil, nil)

	sp := &SPRegistration{
		ID:       "sp1",
		EntityID: "http://sp.example.com",
		ACSUrl:   "http://sp.example.com/acs",
	}
	idp.RegisterSP(sp)

	// Mock hooks to bypass auth and attribute logic
	idp.SetHooks(IdPHooks{
		AuthenticateUser: func(ctx context.Context, r *http.Request) (any, error) {
			return &mockUser{ID: "user1", Traits: []byte(`{"email":"user@example.com"}`)}, nil
		},
	})

	// Create valid AuthnRequest
	req := &AuthnRequest{
		ID:           "_12345",
		Version:      "2.0",
		IssueInstant: time.Now(),
		Issuer:       Issuer{Value: "http://sp.example.com"},
	}
	reqBytes, _ := xml.Marshal(req)
	reqEncoded := base64.StdEncoding.EncodeToString(reqBytes)

	// Create HTTP request
	body := strings.NewReader("SAMLRequest=" + reqEncoded)
	r := httptest.NewRequest("POST", "/sso", body)
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()

	idp.HandleSSORequest(w, r)

	resp := w.Result()
	if resp.StatusCode != 200 {
		t.Errorf("Expected status 200, got %d", resp.StatusCode)
	}

	// Check for HTML response with SAMLResponse
	respBody := w.Body.String()
	if !strings.Contains(respBody, "SAMLResponse") {
		t.Error("Response does not contain SAMLResponse input")
	}
	if !strings.Contains(respBody, sp.ACSUrl) {
		t.Errorf("Response does not target ACS URL: %s", sp.ACSUrl)
	}
}

func TestHandleSSORequest_UnknownSP(t *testing.T) {
	config := IdPServerConfig{
		EntityID: "http://idp.example.com",
	}
	idp := NewIdentityProvider(config, nil, nil)

	req := &AuthnRequest{
		Issuer: Issuer{Value: "http://unknown-sp.com"},
	}
	reqBytes, _ := xml.Marshal(req)
	reqEncoded := base64.StdEncoding.EncodeToString(reqBytes)

	r := httptest.NewRequest("GET", "/sso?SAMLRequest="+reqEncoded, nil)
	w := httptest.NewRecorder()

	idp.HandleSSORequest(w, r)

	if w.Result().StatusCode != http.StatusBadRequest {
		t.Errorf("Expected status 400 for unknown SP, got %d", w.Result().StatusCode)
	}
}

func TestGenerateResponse(t *testing.T) {
	config := IdPServerConfig{
		EntityID:     "http://idp.example.com",
		AssertionTTL: time.Minute,
	}
	idp := NewIdentityProvider(config, nil, nil)
	idp.SetHooks(IdPHooks{
		GetUserAttributes: func(ctx context.Context, ident any, sp *SPRegistration) (map[string][]string, error) {
			return map[string][]string{
				"email": {"test@example.com"},
			}, nil
		},
	})

	sp := &SPRegistration{
		ID:     "sp1",
		ACSUrl: "http://sp.example.com/acs",
	}

	user := &mockUser{ID: "user1", Traits: []byte(`{"email":"test@example.com"}`)}

	respBytes, err := idp.generateResponse(context.Background(), sp, user, "req123")
	if err != nil {
		t.Fatalf("generateResponse failed: %v", err)
	}

	var resp Response
	if err := xml.Unmarshal(respBytes, &resp); err != nil {
		t.Fatalf("Failed to unmarshal generated response: %v", err)
	}

	if resp.Status.StatusCode.Value != "urn:oasis:names:tc:SAML:2.0:status:Success" {
		t.Error("Response status is not Success")
	}
	if resp.Assertion == nil {
		t.Fatal("Response missing Assertion")
	}
	if resp.Assertion.Subject.NameID.Value != "user1" {
		t.Errorf("Expected NameID 'user1', got '%s'", resp.Assertion.Subject.NameID.Value)
	}

	// Check attribute
	foundEmail := false
	for _, attr := range resp.Assertion.AttributeStatement.Attributes {
		if attr.Name == "email" && len(attr.Values) > 0 && attr.Values[0].Value == "test@example.com" {
			foundEmail = true
			break
		}
	}
	if !foundEmail {
		t.Error("Email attribute not found in assertion")
	}
}
