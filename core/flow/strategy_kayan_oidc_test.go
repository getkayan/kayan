package flow

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/getkayan/kayan/core/identity"
	"github.com/google/uuid"
)

// ---- mock oauth ----

type mockOAuthConfig struct {
	authURL     string
	exchangeErr error
	idToken     string
}

func (m *mockOAuthConfig) AuthCodeURL(state string, _ ...AuthCodeOption) string {
	return m.authURL + "?state=" + state
}

func (m *mockOAuthConfig) Exchange(_ context.Context, _ string, _ ...AuthCodeOption) (OAuthToken, error) {
	if m.exchangeErr != nil {
		return nil, m.exchangeErr
	}
	return &mockOAuthToken{idToken: m.idToken}, nil
}

type mockOAuthToken struct{ idToken string }

func (t *mockOAuthToken) Extra(key string) any {
	if key == "id_token" {
		return t.idToken
	}
	return nil
}

// ---- mock token parser ----

type mockIDTokenParser struct {
	claims *IDTokenClaims
	err    error
}

func (p *mockIDTokenParser) ParseAndVerify(_, _, _, _ string) (*IDTokenClaims, error) {
	return p.claims, p.err
}

// ---- mock OIDC repo ----

type mockOIDCRepo struct {
	mu      sync.Mutex
	states  map[string][3]string // state → [verifier, nonce, ttl placeholder]
	idents  map[string]any       // sub → identity
	findErr error
}

func newMockOIDCRepo() *mockOIDCRepo {
	return &mockOIDCRepo{
		states: make(map[string][3]string),
		idents: make(map[string]any),
	}
}

func (r *mockOIDCRepo) StoreOIDCState(_ context.Context, state, verifier, nonce string, _ time.Duration) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.states[state] = [3]string{verifier, nonce, ""}
	return nil
}

func (r *mockOIDCRepo) ConsumeOIDCState(_ context.Context, state string) (string, string, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	v, ok := r.states[state]
	if !ok {
		return "", "", ErrKayanOIDCStateInvalid
	}
	delete(r.states, state)
	return v[0], v[1], nil
}

func (r *mockOIDCRepo) FindOrCreateByProviderSub(_ context.Context, sub string, traits identity.JSON, factory func() any) (any, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.findErr != nil {
		return nil, r.findErr
	}
	if ident, ok := r.idents[sub]; ok {
		return ident, nil
	}
	ident := factory()
	if fi, ok := ident.(FlowIdentity); ok {
		fi.SetID(uuid.NewString())
	}
	r.idents[sub] = ident
	return ident, nil
}

// ---- tests ----

func TestKayanOIDCStrategy_ID(t *testing.T) {
	s := NewKayanOIDCStrategy("", "", "", nil, nil, nil, nil)
	if s.ID() != "kayan_oidc" {
		t.Errorf("ID() = %q, want %q", s.ID(), "kayan_oidc")
	}
}

func TestKayanOIDCStrategy_Initiate(t *testing.T) {
	repo := newMockOIDCRepo()
	oauthCfg := &mockOAuthConfig{authURL: "https://auth.example.com/oauth2/auth"}
	s := NewKayanOIDCStrategy("https://auth.example.com", "client-1", "https://app/callback",
		oauthCfg, nil, repo, func() any { return &identity.Identity{} })

	result, err := s.Initiate(context.Background(), "")
	if err != nil {
		t.Fatalf("Initiate() error: %v", err)
	}
	m, ok := result.(map[string]string)
	if !ok {
		t.Fatalf("Initiate() result type = %T, want map[string]string", result)
	}
	if m["redirect_url"] == "" {
		t.Error("redirect_url is empty")
	}
	if m["state"] == "" {
		t.Error("state is empty")
	}
}

func TestKayanOIDCStrategy_Authenticate(t *testing.T) {
	tests := []struct {
		name         string
		state        string
		code         string
		setupRepo    func(*mockOIDCRepo)
		exchangeErr  error
		idToken      string
		parserErr    error
		parserClaims *IDTokenClaims
		wantErr      error
	}{
		{
			name:         "valid callback",
			state:        "valid-state",
			code:         "auth-code",
			idToken:      "raw.id.token",
			parserClaims: &IDTokenClaims{Sub: "sub-123", Email: "user@example.com"},
		},
		{
			name:    "unknown state",
			state:   "bad-state",
			code:    "any",
			wantErr: ErrKayanOIDCStateInvalid,
		},
		{
			name:        "token exchange failure",
			state:       "valid-state",
			code:        "auth-code",
			exchangeErr: errors.New("network error"),
			wantErr:     errors.New("flow: kayan_oidc: token exchange:"),
		},
		{
			name:    "missing id_token",
			state:   "valid-state",
			code:    "auth-code",
			idToken: "", // triggers ErrKayanOIDCMissingIDToken
			wantErr: ErrKayanOIDCMissingIDToken,
		},
		{
			name:      "id_token verify failure",
			state:     "valid-state",
			code:      "auth-code",
			idToken:   "raw.id.token",
			parserErr: errors.New("sig invalid"),
			wantErr:   ErrKayanOIDCTokenInvalid,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			repo := newMockOIDCRepo()
			// Pre-store valid state
			if tt.state == "valid-state" {
				repo.StoreOIDCState(context.Background(), "valid-state", "verifier", "nonce", 10*time.Minute) //nolint:errcheck
			}
			if tt.setupRepo != nil {
				tt.setupRepo(repo)
			}

			oauthCfg := &mockOAuthConfig{
				authURL:     "https://auth.example.com",
				exchangeErr: tt.exchangeErr,
				idToken:     tt.idToken,
			}
			parser := &mockIDTokenParser{claims: tt.parserClaims, err: tt.parserErr}
			s := NewKayanOIDCStrategy("https://auth.example.com", "client-1", "https://app/callback",
				oauthCfg, parser, repo, func() any { return &identity.Identity{} })

			got, err := s.Authenticate(context.Background(), tt.state, tt.code)

			if tt.wantErr != nil {
				if err == nil {
					t.Errorf("expected error containing %v, got nil", tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got == nil {
				t.Error("expected identity, got nil")
			}
		})
	}
}

func TestKayanOIDCStrategy_StateConsumedOnce(t *testing.T) {
	repo := newMockOIDCRepo()
	repo.StoreOIDCState(context.Background(), "my-state", "ver", "nonce", time.Minute) //nolint:errcheck

	oauthCfg := &mockOAuthConfig{idToken: "raw.id.token"}
	parser := &mockIDTokenParser{claims: &IDTokenClaims{Sub: "sub-1", Email: "u@e.com"}}
	s := NewKayanOIDCStrategy("https://auth.example.com", "c", "https://app/cb",
		oauthCfg, parser, repo, func() any { return &identity.Identity{} })

	if _, err := s.Authenticate(context.Background(), "my-state", "code"); err != nil {
		t.Fatalf("first Authenticate failed: %v", err)
	}
	// State should be consumed — second attempt must fail.
	_, err := s.Authenticate(context.Background(), "my-state", "code")
	if !errors.Is(err, ErrKayanOIDCStateInvalid) {
		t.Errorf("second use error = %v, want ErrKayanOIDCStateInvalid", err)
	}
}
