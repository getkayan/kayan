package flow

import "errors"

var (
	// ErrIdentityAlreadyExists is returned when a registration attempt matches an existing identity
	// but the duplicate policy prevents automatic linking/capture.
	ErrIdentityAlreadyExists = errors.New("registration: identity already exists")

	// ErrAccountInactive is returned after credentials verify when the identity
	// is disabled, locked, or pending. Public handlers should still return the
	// same generic response used for invalid credentials.
	ErrAccountInactive = errors.New("login: account is not active")

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

	// ErrLDAPSearchFailed reports that the directory refused or could not
	// complete the user search.
	//
	// It is distinct from ErrLDAPUserNotFound on purpose. Reporting a failed
	// search as "no such user" turns a directory outage, a mistyped base DN,
	// or a size-limit refusal into an authentication failure that looks like
	// the user's fault: every login is rejected, the user sees invalid
	// credentials, and nothing anywhere reports that the directory is the
	// problem.
	ErrLDAPSearchFailed = errors.New("ldap: user search failed")

	// ErrLDAPAmbiguousUser reports that the username matched more than one
	// directory entry.
	//
	// LDAP does not enforce attribute uniqueness. OpenLDAP has no unique
	// constraint unless the uniqueness overlay is configured, and a subtree
	// search spans every OU under the base DN, so two entries sharing a uid is
	// a configuration a directory will happily hold. Authenticating against
	// whichever one the server listed first makes the answer depend on the
	// replica that served the search.
	ErrLDAPAmbiguousUser = errors.New("ldap: username matched more than one directory entry")

	// ErrLDAPResultTruncated reports that the directory returned fewer entries
	// than matched the filter, because a size limit stopped it.
	//
	// It is returned alongside the partial entries so a caller can tell a
	// complete small result from a truncated large one. Active Directory
	// applies MaxPageSize (1000 by default) to any search that does not carry
	// the paged-results control, so this is reachable on a real directory
	// rather than only on a misconfigured one.
	ErrLDAPResultTruncated = errors.New("ldap: search result was truncated by a size limit")

	// WebAuthn errors.
	ErrWebAuthnClonedCredential = errors.New("webauthn: authenticator signature counter went backwards; credential may be cloned")

	// Step-up errors.
	ErrStepUpNoPolicy = errors.New("stepup: no policy configured")

	// Kayan OIDC errors.
	ErrKayanOIDCStateInvalid   = errors.New("kayan_oidc: state invalid or expired")
	ErrKayanOIDCStateExpired   = errors.New("kayan_oidc: state expired")
	ErrKayanOIDCMissingIDToken = errors.New("kayan_oidc: id_token missing from response")
	ErrKayanOIDCTokenInvalid   = errors.New("kayan_oidc: id token invalid")
	ErrKayanOIDCNonceMismatch  = errors.New("kayan_oidc: nonce mismatch")
)
