package flow

import (
	"context"
	"errors"
	"testing"

	"github.com/getkayan/kayan/core/identity"
)

func TestPasswordPolicy_Validate(t *testing.T) {
	tests := []struct {
		name     string
		policy   PasswordPolicy
		password string
		wantErr  error
	}{
		{
			name:     "default policy accepts valid password",
			policy:   DefaultPasswordPolicy,
			password: "validpass",
			wantErr:  nil,
		},
		{
			name:     "too short",
			policy:   PasswordPolicy{MinLength: 8, MaxLength: 128},
			password: "short",
			wantErr:  ErrPasswordTooShort,
		},
		{
			name:     "too long",
			policy:   PasswordPolicy{MinLength: 1, MaxLength: 10},
			password: "thisissuperlong",
			wantErr:  ErrPasswordTooLong,
		},
		{
			name:     "requires uppercase missing",
			policy:   PasswordPolicy{MinLength: 1, MaxLength: 128, RequireUppercase: true},
			password: "alllowercase",
			wantErr:  ErrPasswordNoUpper,
		},
		{
			name:     "requires uppercase present",
			policy:   PasswordPolicy{MinLength: 1, MaxLength: 128, RequireUppercase: true},
			password: "hasUpperA",
			wantErr:  nil,
		},
		{
			name:     "requires lowercase missing",
			policy:   PasswordPolicy{MinLength: 1, MaxLength: 128, RequireLowercase: true},
			password: "ALLUPPERCASE",
			wantErr:  ErrPasswordNoLower,
		},
		{
			name:     "requires digit missing",
			policy:   PasswordPolicy{MinLength: 1, MaxLength: 128, RequireDigit: true},
			password: "nodigits",
			wantErr:  ErrPasswordNoDigit,
		},
		{
			name:     "requires digit present",
			policy:   PasswordPolicy{MinLength: 1, MaxLength: 128, RequireDigit: true},
			password: "has1digit",
			wantErr:  nil,
		},
		{
			name:     "requires special missing",
			policy:   PasswordPolicy{MinLength: 1, MaxLength: 128, RequireSpecial: true},
			password: "noSpecial1",
			wantErr:  ErrPasswordNoSpecial,
		},
		{
			name:     "requires special present",
			policy:   PasswordPolicy{MinLength: 1, MaxLength: 128, RequireSpecial: true},
			password: "has!special",
			wantErr:  nil,
		},
		{
			name: "all complexity rules pass",
			policy: PasswordPolicy{
				MinLength:        8,
				MaxLength:        128,
				RequireUppercase: true,
				RequireLowercase: true,
				RequireDigit:     true,
				RequireSpecial:   true,
			},
			password: "Complex1!",
			wantErr:  nil,
		},
		{
			name:     "zero max length means no limit",
			policy:   PasswordPolicy{MinLength: 1, MaxLength: 0},
			password: "this can be as long as we want with no limit at all",
			wantErr:  nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.policy.Validate(tt.password)
			if tt.wantErr == nil {
				if err != nil {
					t.Fatalf("expected no error, got %v", err)
				}
				return
			}
			if err == nil {
				t.Fatalf("expected error %v, got nil", tt.wantErr)
			}
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("expected error %v, got %v", tt.wantErr, err)
			}
		})
	}
}

func TestPasswordPolicy_CustomValidator(t *testing.T) {
	errBanned := errors.New("banned password")
	policy := PasswordPolicy{
		MinLength: 1,
		MaxLength: 128,
		CustomValidator: func(pw string) error {
			if pw == "password" {
				return errBanned
			}
			return nil
		},
	}

	if err := policy.Validate("password"); err != errBanned {
		t.Fatalf("expected banned error, got %v", err)
	}
	if err := policy.Validate("goodpassword"); err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
}

func TestPasswordStrategy_PolicyEnforcement(t *testing.T) {
	repo := &mockRepo{
		identities: make(map[string]any),
		creds:      make(map[string]*identity.Credential),
	}
	factory := func() any { return &identity.Identity{} }

	strategy := NewPasswordStrategy(repo, NewBcryptHasher(4), "email", factory)
	strictPolicy := &PasswordPolicy{
		MinLength:        10,
		MaxLength:        128,
		RequireUppercase: true,
		RequireDigit:     true,
	}
	strategy.SetPasswordPolicy(strictPolicy)

	traits := identity.JSON(`{"email": "policy@example.com"}`)

	// Too short
	_, err := strategy.Register(context.Background(), traits, "Short1")
	if !errors.Is(err, ErrPasswordTooShort) {
		t.Fatalf("expected ErrPasswordTooShort, got %v", err)
	}

	// No uppercase
	_, err = strategy.Register(context.Background(), traits, "alllowercase1")
	if !errors.Is(err, ErrPasswordNoUpper) {
		t.Fatalf("expected ErrPasswordNoUpper, got %v", err)
	}

	// No digit
	_, err = strategy.Register(context.Background(), traits, "AllLettersUpper")
	if !errors.Is(err, ErrPasswordNoDigit) {
		t.Fatalf("expected ErrPasswordNoDigit, got %v", err)
	}

	// Valid
	_, err = strategy.Register(context.Background(), traits, "ValidPass1!")
	if err != nil {
		t.Fatalf("expected success, got %v", err)
	}
}
