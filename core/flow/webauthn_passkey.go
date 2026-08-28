package flow

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"fmt"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
)

// Errors specific to discoverable-credential (passkey) login.
var (
	// ErrNoDiscoverableUserLoader reports that a discoverable login was
	// attempted with no way to resolve the user handle.
	//
	// It fails closed rather than falling back to the identifier-based path,
	// because a discoverable ceremony carries no identifier: there is nothing
	// to fall back to, and the alternative shape -- trusting whichever
	// credential the assertion names -- authenticates whoever presents one.
	ErrNoDiscoverableUserLoader = errors.New("webauthn: discoverable login requires a DiscoverableUserLoader hook")

	// ErrUnknownDiscoverableCredential reports a user handle that resolved to
	// no identity.
	ErrUnknownDiscoverableCredential = errors.New("webauthn: no identity owns this credential")

	// ErrUserHandleMismatch reports an identity whose ID is not the user
	// handle the authenticator asserted.
	//
	// The user handle is the only thing naming a subject in a discoverable
	// ceremony. A loader that returned some other identity -- from a stale
	// index, or a lookup keyed on the credential ID alone after a credential
	// was reassigned -- would authenticate the wrong person with a valid
	// signature, and nothing else in the ceremony would notice.
	ErrUserHandleMismatch = errors.New("webauthn: resolved identity does not match the asserted user handle")
)

// PasskeyAuthenticatorSelection returns the authenticator selection criteria
// for a passkey: a discoverable credential with user verification.
//
// Both halves matter. Without a resident key the credential cannot be found
// without a username, so there is no usernameless sign-in. Without user
// verification the ceremony proves possession of the authenticator and nothing
// about who is holding it, which is a single factor -- and the reason to move
// to passkeys is that they are two.
func PasskeyAuthenticatorSelection() protocol.AuthenticatorSelection {
	required := true
	return protocol.AuthenticatorSelection{
		ResidentKey:        protocol.ResidentKeyRequirementRequired,
		RequireResidentKey: &required,
		UserVerification:   protocol.VerificationRequired,
	}
}

// BeginDiscoverableLogin starts a login ceremony with no identifier.
//
// The authenticator chooses which credential to present and reports the user
// handle it belongs to, so the sign-in needs no username. This is the passkey
// flow; it works only for credentials registered as discoverable, which needs
// [WebAuthnConfig.AuthenticatorSelection].
//
// User verification is required for this ceremony unless the deployment
// overrides it. A usernameless sign-in with no user verification proves
// possession of an authenticator and nothing about who is holding it.
func (s *WebAuthnStrategy) BeginDiscoverableLogin(ctx context.Context) (*protocol.CredentialAssertion, string, error) {
	hooks := s.getHooks()
	if hooks.DiscoverableUserLoader == nil {
		return nil, "", ErrNoDiscoverableUserLoader
	}

	options, session, err := s.webAuthn.BeginDiscoverableLogin(
		webauthn.WithUserVerification(s.discoverableUserVerification()),
	)
	if err != nil {
		return nil, "", fmt.Errorf("webauthn: begin discoverable login failed: %w", err)
	}

	sessionID := s.newSessionID(hooks)
	sessionData := &WebAuthnSessionData{
		Challenge: session.Challenge,
		// UserID stays empty on purpose: it is what marks the session as
		// discoverable, and the library refuses to validate a discoverable
		// assertion against a session that names a user.
		UserVerification: string(session.UserVerification),
		Discoverable:     true,
		ExpiresAt:        s.clock.Now().Add(s.sessionTTL),
	}

	if err := s.sessionStore.SaveSession(ctx, sessionID, sessionData); err != nil {
		return nil, "", fmt.Errorf("webauthn: failed to save session: %w", err)
	}

	return options, sessionID, nil
}

// FinishDiscoverableLogin completes a passkey login.
//
// The identity comes from the user handle the authenticator asserted, resolved
// through [WebAuthnHooks.DiscoverableUserLoader]. Everything else -- the
// signature, the challenge, the origin, the credential belonging to that
// identity, the signature counter -- is checked exactly as in the
// identifier-based flow.
func (s *WebAuthnStrategy) FinishDiscoverableLogin(
	ctx context.Context,
	sessionID string,
	response *protocol.ParsedCredentialAssertionData,
) (any, error) {
	hooks := s.getHooks()
	loader := hooks.DiscoverableUserLoader
	if loader == nil {
		return nil, ErrNoDiscoverableUserLoader
	}

	sessionData, err := s.sessionStore.GetSession(ctx, sessionID)
	if err != nil {
		return nil, fmt.Errorf("webauthn: session not found: %w", err)
	}
	// Single-use, whatever happens next. A challenge left live after a failed
	// attempt can be retried, which is the whole value of it being a nonce.
	defer func() { _ = s.sessionStore.DeleteSession(ctx, sessionID) }()

	if s.clock.Now().After(sessionData.ExpiresAt) {
		return nil, errors.New("webauthn: session expired")
	}
	// A session begun as an identifier-based ceremony must not be finished as
	// a discoverable one. That session named a user and constrained the
	// allowed credentials; completing it through this path would discard both
	// and let the assertion nominate its own subject.
	if !sessionData.Discoverable {
		return nil, errors.New("webauthn: session was not begun as a discoverable login")
	}

	var resolved any
	handler := s.discoverableUserHandler(ctx, loader, &resolved)

	waSession := webauthn.SessionData{
		Challenge:        sessionData.Challenge,
		UserVerification: protocol.UserVerificationRequirement(sessionData.UserVerification),
	}

	credential, err := s.webAuthn.ValidateDiscoverableLogin(handler, waSession, response)
	if err != nil {
		return nil, fmt.Errorf("webauthn: discoverable login validation failed: %w", err)
	}
	if resolved == nil {
		// Unreachable while the handler is the only path to a credential, but
		// returning nil with no error here would hand the caller an
		// authenticated nobody.
		return nil, ErrUnknownDiscoverableCredential
	}

	// Persisted before the clone check so the evidence survives a refused
	// login; otherwise the next attempt starts from a clean counter.
	if err := s.updateSignCount(ctx, resolved, credential); err != nil {
		return nil, fmt.Errorf("webauthn: failed to persist sign count: %w", err)
	}

	if credential.Authenticator.CloneWarning {
		credID := base64.RawURLEncoding.EncodeToString(credential.ID)
		if hooks.OnCloneWarning != nil {
			hooks.OnCloneWarning(ctx, resolved, credID)
		}
		if !hooks.AllowClonedAuthenticators {
			return nil, fmt.Errorf("%w: credential %s", ErrWebAuthnClonedCredential, credID)
		}
	}

	if hooks.AfterFinishLogin != nil {
		if err := hooks.AfterFinishLogin(ctx, resolved); err != nil {
			return nil, err
		}
	}

	return resolved, nil
}

// discoverableUserHandler adapts a DiscoverableUserLoader for the library, and
// is where the user handle is checked.
//
// resolved receives the identity, so the caller keeps its own type rather than
// the webauthn.User wrapper.
//
// This is the security-critical part of a passkey login and it is a named
// function so it can be tested without a real authenticator: reaching it
// through ValidateDiscoverableLogin needs a genuine assertion, and a check
// that cannot be exercised is a check nobody knows is working.
func (s *WebAuthnStrategy) discoverableUserHandler(
	ctx context.Context,
	loader func(context.Context, []byte, []byte) (any, error),
	resolved *any,
) webauthn.DiscoverableUserHandler {
	return func(rawID, userHandle []byte) (webauthn.User, error) {
		ident, err := loader(ctx, rawID, userHandle)
		if err != nil {
			return nil, err
		}
		if ident == nil {
			return nil, ErrUnknownDiscoverableCredential
		}
		fi, ok := ident.(FlowIdentity)
		if !ok {
			return nil, errors.New("webauthn: identity must implement FlowIdentity")
		}

		// The user handle is the only thing naming a subject here. A loader
		// that returned a different identity -- from a stale index, or a
		// lookup keyed on the credential id alone after that credential was
		// reassigned -- would authenticate the wrong person with a perfectly
		// valid signature, and nothing else in the ceremony would notice.
		id := []byte(fmt.Sprintf("%v", fi.GetID()))
		if !bytes.Equal(id, userHandle) {
			return nil, fmt.Errorf("%w: handle %q resolved to identity %q",
				ErrUserHandleMismatch,
				base64.RawURLEncoding.EncodeToString(userHandle), id)
		}

		*resolved = ident
		return &WebAuthnUser{
			id:          id,
			name:        fmt.Sprintf("%v", fi.GetID()),
			displayName: fmt.Sprintf("%v", fi.GetID()),
			credentials: s.getExistingCredentials(ident),
		}, nil
	}
}

// discoverableUserVerification returns the user-verification requirement for a
// discoverable ceremony.
//
// It defaults to required rather than inheriting the registration preference,
// because a usernameless sign-in without it is a single factor.
func (s *WebAuthnStrategy) discoverableUserVerification() protocol.UserVerificationRequirement {
	if s.config.DiscoverableUserVerification != "" {
		return s.config.DiscoverableUserVerification
	}
	return protocol.VerificationRequired
}

// registrationOptions builds the per-ceremony options from configuration.
func (s *WebAuthnStrategy) registrationOptions() []webauthn.RegistrationOption {
	var opts []webauthn.RegistrationOption
	if s.config.AuthenticatorSelection != nil {
		opts = append(opts, webauthn.WithAuthenticatorSelection(*s.config.AuthenticatorSelection))
	}
	if s.config.AttestationPreference != "" {
		opts = append(opts, webauthn.WithConveyancePreference(s.config.AttestationPreference))
	}
	return opts
}
