package flow

import (
	"errors"
	"fmt"
	"unicode"
)

// Password policy sentinel errors.
var (
	ErrPasswordTooShort  = errors.New("flow: password too short")
	ErrPasswordTooLong   = errors.New("flow: password too long")
	ErrPasswordNoUpper   = errors.New("flow: password must contain an uppercase letter")
	ErrPasswordNoLower   = errors.New("flow: password must contain a lowercase letter")
	ErrPasswordNoDigit   = errors.New("flow: password must contain a digit")
	ErrPasswordNoSpecial = errors.New("flow: password must contain a special character")
)

// PasswordPolicy defines rules for password strength validation.
type PasswordPolicy struct {
	MinLength        int
	MaxLength        int
	RequireUppercase bool
	RequireLowercase bool
	RequireDigit     bool
	RequireSpecial   bool
	CustomValidator  func(string) error
}

// DefaultPasswordPolicy enforces a minimum length of 8 and maximum of 128
// with no complexity requirements. Consumers can override with stricter rules.
var DefaultPasswordPolicy = PasswordPolicy{
	MinLength: 8,
	MaxLength: 128,
}

// Validate checks the password against the policy rules.
func (p *PasswordPolicy) Validate(password string) error {
	if len(password) < p.MinLength {
		return fmt.Errorf("%w: minimum %d characters", ErrPasswordTooShort, p.MinLength)
	}
	if p.MaxLength > 0 && len(password) > p.MaxLength {
		return fmt.Errorf("%w: maximum %d characters", ErrPasswordTooLong, p.MaxLength)
	}

	if p.RequireUppercase || p.RequireLowercase || p.RequireDigit || p.RequireSpecial {
		var hasUpper, hasLower, hasDigit, hasSpecial bool
		for _, r := range password {
			switch {
			case unicode.IsUpper(r):
				hasUpper = true
			case unicode.IsLower(r):
				hasLower = true
			case unicode.IsDigit(r):
				hasDigit = true
			case unicode.IsPunct(r) || unicode.IsSymbol(r):
				hasSpecial = true
			}
		}
		if p.RequireUppercase && !hasUpper {
			return ErrPasswordNoUpper
		}
		if p.RequireLowercase && !hasLower {
			return ErrPasswordNoLower
		}
		if p.RequireDigit && !hasDigit {
			return ErrPasswordNoDigit
		}
		if p.RequireSpecial && !hasSpecial {
			return ErrPasswordNoSpecial
		}
	}

	if p.CustomValidator != nil {
		return p.CustomValidator(password)
	}

	return nil
}
