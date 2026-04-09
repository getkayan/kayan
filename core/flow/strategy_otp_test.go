package flow

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/getkayan/kayan/core/domain"
	"github.com/getkayan/kayan/core/identity"
)

// --- Mock OTP Sender ---

type mockOTPSender struct {
	mu       sync.Mutex
	sent     map[string]string // recipient -> code
	failNext bool
}

func newMockOTPSender() *mockOTPSender {
	return &mockOTPSender{sent: make(map[string]string)}
}

func (s *mockOTPSender) Send(ctx context.Context, recipient, code string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.failNext {
		s.failNext = false
		return errors.New("delivery failed")
	}
	s.sent[recipient] = code
	return nil
}

func (s *mockOTPSender) lastCode(recipient string) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.sent[recipient]
}

// --- Test Helpers ---

func setupOTPTest(t *testing.T) (*OTPStrategy, *mockOTPSender, *mockTokenStore, *mockRepo) {
	t.Helper()

	repo := &mockRepo{
		identities: make(map[string]any),
		creds:      make(map[string]*identity.Credential),
	}

	// Pre-register an identity with a credential
	ident := &identity.Identity{ID: "user-1"}
	ident.SetTraits(identity.JSON(`{"email": "test@example.com"}`))
	repo.identities["user-1"] = ident
	repo.creds["test@example.com:password"] = &identity.Credential{
		ID:         "cred-1",
		IdentityID: "user-1",
		Type:       "password",
		Identifier: "test@example.com",
	}

	sender := newMockOTPSender()
	tokenStore := &mockTokenStore{
		tokens: make(map[string]*domain.AuthToken),
	}

	strategy := NewOTPStrategy(repo, tokenStore, sender)

	return strategy, sender, tokenStore, repo
}

// --- Tests ---

func TestOTPStrategy_ID(t *testing.T) {
	strategy := &OTPStrategy{}
	if strategy.ID() != "otp" {
		t.Errorf("expected ID 'otp', got %q", strategy.ID())
	}
}

func TestOTPStrategy_Initiate_And_Authenticate(t *testing.T) {
	tests := []struct {
		name        string
		identifier  string
		setupFn     func(*OTPStrategy, *mockOTPSender, *mockTokenStore)
		wantInitErr bool
		wantAuthErr bool
	}{
		{
			name:       "valid flow: initiate and authenticate",
			identifier: "test@example.com",
		},
		{
			name:        "unknown user",
			identifier:  "unknown@example.com",
			wantInitErr: true,
		},
		{
			name:       "sender failure",
			identifier: "test@example.com",
			setupFn: func(s *OTPStrategy, sender *mockOTPSender, ts *mockTokenStore) {
				sender.failNext = true
			},
			wantInitErr: true,
		},
		{
			name:       "expired code",
			identifier: "test@example.com",
			setupFn: func(s *OTPStrategy, sender *mockOTPSender, ts *mockTokenStore) {
				s.ttl = -1 * time.Second // Already expired
			},
			wantAuthErr: true,
		},
		{
			name:       "code replay (used twice)",
			identifier: "test@example.com",
			wantAuthErr: true, // Second use should fail
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			strategy, sender, tokenStore, _ := setupOTPTest(t)

			if tt.setupFn != nil {
				tt.setupFn(strategy, sender, tokenStore)
			}

			// Initiate
			result, err := strategy.Initiate(context.Background(), tt.identifier)
			if tt.wantInitErr {
				if err == nil {
					t.Fatal("expected initiation error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected initiation error: %v", err)
			}

			token, ok := result.(*domain.AuthToken)
			if !ok {
				t.Fatal("expected *domain.AuthToken result")
			}

			// Verify code was sent
			sentCode := sender.lastCode(tt.identifier)
			if sentCode == "" {
				t.Fatal("expected code to be sent")
			}
			if sentCode != token.Token {
				t.Errorf("sent code %q != token code %q", sentCode, token.Token)
			}

			// Verify code length
			if len(sentCode) != 6 {
				t.Errorf("expected 6-digit code, got %d digits: %q", len(sentCode), sentCode)
			}

			// Authenticate with the code
			ident, err := strategy.Authenticate(context.Background(), tt.identifier, sentCode)

			if tt.name == "code replay (used twice)" {
				// First auth should succeed
				if err != nil {
					t.Fatalf("first auth failed: %v", err)
				}
				if ident == nil {
					t.Fatal("expected identity, got nil")
				}
				// Second auth should fail (code consumed)
				_, err = strategy.Authenticate(context.Background(), tt.identifier, sentCode)
				if err == nil {
					t.Fatal("expected replay error, got nil")
				}
				return
			}

			if tt.wantAuthErr {
				if err == nil {
					t.Fatal("expected auth error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected auth error: %v", err)
			}
			if ident == nil {
				t.Fatal("expected identity, got nil")
			}
		})
	}
}

func TestOTPStrategy_NilSender(t *testing.T) {
	repo := &mockRepo{
		identities: make(map[string]any),
		creds:      make(map[string]*identity.Credential),
	}
	tokenStore := &mockTokenStore{
		tokens: make(map[string]*domain.AuthToken),
	}

	strategy := NewOTPStrategy(repo, tokenStore, nil)
	_, err := strategy.Initiate(context.Background(), "test@example.com")
	if err == nil {
		t.Fatal("expected error for nil sender")
	}
}

func TestOTPStrategy_CustomCodeLength(t *testing.T) {
	strategy, sender, _, _ := setupOTPTest(t)
	strategy.codeLength = 8

	_, err := strategy.Initiate(context.Background(), "test@example.com")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	code := sender.lastCode("test@example.com")
	if len(code) != 8 {
		t.Errorf("expected 8-digit code, got %d digits: %q", len(code), code)
	}
}

func TestOTPStrategy_InvalidCode(t *testing.T) {
	strategy, _, _, _ := setupOTPTest(t)

	_, err := strategy.Authenticate(context.Background(), "test@example.com", "000000")
	if err == nil {
		t.Fatal("expected error for invalid code")
	}
}

func TestOTPStrategy_GenerateCode(t *testing.T) {
	strategy := &OTPStrategy{codeLength: 6}
	seen := make(map[string]bool)

	// Generate 100 codes and verify they're all valid and mostly unique
	for i := 0; i < 100; i++ {
		code, err := strategy.generateCode()
		if err != nil {
			t.Fatalf("generateCode failed: %v", err)
		}
		if len(code) != 6 {
			t.Errorf("expected 6-digit code, got %d digits: %q", len(code), code)
		}
		// Verify all characters are digits
		for _, c := range code {
			if c < '0' || c > '9' {
				t.Errorf("non-digit character in code: %c", c)
			}
		}
		seen[code] = true
	}

	// With 6-digit codes, 100 random codes should have some uniqueness
	if len(seen) < 50 {
		t.Errorf("too many collisions: only %d unique codes from 100 generated", len(seen))
	}
}
