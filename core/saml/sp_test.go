package saml

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/xml"
	"fmt"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/getkayan/kayan/core/identity"
)

// --- Mocks ---

type mockSessionStore struct {
	sessions map[string]*Session
}

func newMockSessionStore() *mockSessionStore {
	return &mockSessionStore{
		sessions: make(map[string]*Session),
	}
}

func (m *mockSessionStore) Save(ctx context.Context, session *Session) error {
	m.sessions[session.ID] = session
	return nil
}

func (m *mockSessionStore) Get(ctx context.Context, id string) (*Session, error) {
	if s, ok := m.sessions[id]; ok {
		return s, nil
	}
	return nil, context.DeadlineExceeded // simulate not found/error
}

func (m *mockSessionStore) GetByRequestID(ctx context.Context, requestID string) (*Session, error) {
	for _, s := range m.sessions {
		if s.RequestID == requestID {
			return s, nil
		}
	}
	return nil, context.DeadlineExceeded
}

func (m *mockSessionStore) Delete(ctx context.Context, id string) error {
	delete(m.sessions, id)
	return nil
}

type mockIdentityRepo struct {
	identities map[string]any
}

func newMockIdentityRepo() *mockIdentityRepo {
	return &mockIdentityRepo{
		identities: make(map[string]any),
	}
}

func (m *mockIdentityRepo) GetIdentity(factory func() any, id any) (any, error) {
	return nil, nil
}
func (m *mockIdentityRepo) CreateIdentity(identity any) error {
	return nil
}
func (m *mockIdentityRepo) UpdateIdentity(identity any) error {
	return nil
}
func (m *mockIdentityRepo) DeleteIdentity(id any) error {
	return nil
}
func (m *mockIdentityRepo) FindIdentity(factory func() any, query map[string]any) (any, error) {
	return nil, nil
}
func (m *mockIdentityRepo) ListIdentities(factory func() any, page, limit int) ([]any, error) {
	return nil, nil
}
func (m *mockIdentityRepo) GetCredentialByIdentifier(identifier string, method string) (*identity.Credential, error) {
	return nil, fmt.Errorf("credential not found") // domain.ErrCredentialNotFound invalid
}
func (m *mockIdentityRepo) UpdateCredentialSecret(ctx context.Context, identityID, method, secret string) error {
	return nil
}

type mockUser struct {
	ID     string
	Traits identity.JSON
}

func (u *mockUser) GetID() any {
	return u.ID
}
func (u *mockUser) SetID(id any) {
	u.ID = id.(string)
}
func (u *mockUser) GetTraits() identity.JSON {
	return u.Traits
}
func (u *mockUser) SetTraits(traits identity.JSON) {
	u.Traits = traits
}

// --- Helpers ---

func generateTestCert() (*x509.Certificate, *rsa.PrivateKey) {
	priv, _ := rsa.GenerateKey(rand.Reader, 2048)
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"Test Org"},
		},
		NotBefore: time.Now(),
		NotAfter:  time.Now().Add(time.Hour),
	}
	derBytes, _ := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	cert, _ := x509.ParseCertificate(derBytes)
	return cert, priv
}

// --- Tests ---

func TestNewServiceProvider(t *testing.T) {
	config := Config{
		EntityID: "http://sp.example.com",
		ACSUrl:   "http://sp.example.com/acs",
	}
	repo := newMockIdentityRepo()
	store := newMockSessionStore()
	factory := func() any { return &mockUser{} }

	sp := NewServiceProvider(config, store, repo, factory)
	if sp == nil {
		t.Fatal("NewServiceProvider returned nil")
	}
}

func TestInitiateLogin(t *testing.T) {
	config := Config{
		EntityID: "http://sp.example.com",
		ACSUrl:   "http://sp.example.com/acs",
	}
	repo := newMockIdentityRepo()
	store := newMockSessionStore()
	factory := func() any { return &mockUser{} }
	sp := NewServiceProvider(config, store, repo, factory)

	idp := &IdPConfig{
		ID:     "idp1",
		SSOUrl: "http://idp.example.com/sso",
	}
	sp.RegisterIdP(idp)

	redirectURL, err := sp.InitiateLogin(context.Background(), "idp1", "/dashboard")
	if err != nil {
		t.Fatalf("InitiateLogin failed: %v", err)
	}

	if !strings.Contains(redirectURL, "http://idp.example.com/sso") {
		t.Errorf("Redirect URL does not contain IdP SSO URL: %s", redirectURL)
	}
	if !strings.Contains(redirectURL, "SAMLRequest=") {
		t.Error("Redirect URL missing SAMLRequest param")
	}
	if !strings.Contains(redirectURL, "RelayState=") {
		t.Error("Redirect URL missing RelayState param")
	}
}

func TestProcessResponse(t *testing.T) {
	config := Config{
		EntityID: "http://sp.example.com",
		ACSUrl:   "http://sp.example.com/acs",
	}
	repo := newMockIdentityRepo()
	store := newMockSessionStore()
	factory := func() any { return &mockUser{} }
	sp := NewServiceProvider(config, store, repo, factory)

	idp := &IdPConfig{
		ID:     "idp1",
		SSOUrl: "http://idp.example.com/sso",
	}
	sp.RegisterIdP(idp)

	// Manually create a session
	sessionID := "test-session"
	requestID := "request-123"
	store.Save(context.Background(), &Session{
		ID:        sessionID,
		RequestID: requestID,
		IdPID:     "idp1",
	})

	// Create a dummy SAML response
	// Note: In a real test we'd need a valid signed XML.
	// Here we mock the parsing/validation if possible, or construct a minimal valid XML that passes unmarshal.
	// Since ProcessResponse does validation, we need to be careful.
	// For this unit test, let's create a response that matches what we expect unmarshaled.

	resp := Response{
		InResponseTo: requestID,
		Status: Status{
			StatusCode: StatusCode{Value: "urn:oasis:names:tc:SAML:2.0:status:Success"},
		},
		Assertion: &Assertion{
			Subject: Subject{
				NameID: NameID{Value: "user@example.com"},
			},
			AttributeStatement: AttributeStatement{
				Attributes: []Attribute{
					{Name: "email", Values: []AttributeValue{{Value: "user@example.com"}}},
				},
			},
		},
	}

	respBytes, _ := xml.Marshal(resp)
	encodedResp := base64.StdEncoding.EncodeToString(respBytes)

	user, err := sp.ProcessResponse(context.Background(), encodedResp, sessionID)
	if err != nil {
		t.Fatalf("ProcessResponse failed: %v", err)
	}

	u := user.(*mockUser)
	// The default factory creates a user but reconcileIdentity might not set ID if it's new
	// But it should have traits set from attributes
	traitsStr := string(u.Traits)
	if !strings.Contains(traitsStr, "user@example.com") {
		t.Errorf("User traits missing email: %s", traitsStr)
	}
}
