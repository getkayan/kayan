package flow

import "errors"

var (
	// ErrIdentityAlreadyExists is returned when a registration attempt matches an existing identity
	// but the duplicate policy prevents automatic linking/capture.
	ErrIdentityAlreadyExists = errors.New("registration: identity already exists")

	// ErrRecoveryRateLimited is returned when recovery requests exceed the rate limit.
	ErrRecoveryRateLimited = errors.New("recovery: rate limited")

	// ErrTOTPCodeInvalid is returned when the TOTP code does not match within any valid time window.
	ErrTOTPCodeInvalid = errors.New("totp: code invalid")

	// ErrTOTPReplay is returned when the TOTP time-step counter was already used (replay attack).
	ErrTOTPReplay = errors.New("totp: code already used")

	// ErrTOTPSecretNotFound is returned when no TOTP secret is configured for the identity.
	ErrTOTPSecretNotFound = errors.New("totp: secret not found")

	// API Key errors.
	ErrAPIKeyInvalid           = errors.New("api_key: invalid or expired key")
	ErrAPIKeyExpired           = errors.New("api_key: key expired")
	ErrAPIKeyScopeInsufficient = errors.New("api_key: insufficient scope")

	// Recovery code errors.
	ErrRecoveryCodeInvalid      = errors.New("recovery_code: invalid code")
	ErrRecoveryCodeAlreadyUsed  = errors.New("recovery_code: code already used")
	ErrNoRecoveryCodesRemaining = errors.New("recovery_code: no unused codes remaining")

	// LDAP errors.
	ErrLDAPInvalidCredentials = errors.New("ldap: invalid credentials")
	ErrLDAPUserNotFound       = errors.New("ldap: user not found")
	ErrLDAPConnectionFailed   = errors.New("ldap: connection failed")

	// Kayan OIDC errors.
	ErrKayanOIDCStateInvalid   = errors.New("kayan_oidc: state invalid or expired")
	ErrKayanOIDCStateExpired   = errors.New("kayan_oidc: state expired")
	ErrKayanOIDCMissingIDToken = errors.New("kayan_oidc: id_token missing from response")
	ErrKayanOIDCTokenInvalid   = errors.New("kayan_oidc: id token invalid")
	ErrKayanOIDCNonceMismatch  = errors.New("kayan_oidc: nonce mismatch")
)
