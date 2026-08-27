package flow

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"

	"github.com/getkayan/kayan/core/identity"
)

// linkingRepo models the lookup the linking path actually performs. The
// production query is FindIdentity(ctx, factory, {"email": ...}), which GORM
// resolves as a column name and therefore matches the Email field
// case-insensitively. The shared mockRepo compares with FieldByName, which is
// case-sensitive and so never matches "email" -- an artefact of the fake, not
// of the library.
type linkingRepo struct {
	*mockRepo
}

func (r *linkingRepo) FindIdentity(ctx context.Context, factory func() any, query map[string]any) (any, error) {
	email, ok := query["email"].(string)
	if !ok {
		return nil, nil
	}
	for _, ident := range r.mockRepo.identities {
		if u, ok := ident.(*linkableUser); ok && u.Email == email {
			return u, nil
		}
	}
	return nil, nil
}

// newLinkingManager builds an OIDCManager without going through
// NewOIDCManager, which dials every configured issuer. Only reconcileIdentity
// is under test here, and it touches nothing but the repository.
func newLinkingManager(repo IdentityRepository) *OIDCManager {
	return &OIDCManager{
		repo:    repo,
		factory: func() any { return &linkableUser{} },
	}
}

// linkableUser is a caller-owned identity with the email as a real field.
//
// The linking lookup is FindIdentity(ctx, factory, {"email": ...}), which
// matches on a stored attribute. A model that keeps its email inside an opaque
// traits blob is never found by that query, so the takeover is only reachable
// for applications whose schema exposes the address -- which is the ordinary
// BYOS shape the library is built for.
type linkableUser struct {
	ID    string
	Email string
}

func (u *linkableUser) GetID() any                             { return u.ID }
func (u *linkableUser) SetID(id any)                           { u.ID = fmt.Sprintf("%v", id) }
func (u *linkableUser) GetCredentials() []identity.Credential  { return nil }
func (u *linkableUser) SetCredentials(c []identity.Credential) {}

// seedVictim registers an existing local account that an attacker will try to
// take over by claiming its email address at a federated provider.
func seedVictim(t *testing.T) *mockRepo {
	t.Helper()

	repo := &mockRepo{
		identities: make(map[string]any),
		creds:      make(map[string]*identity.Credential),
	}
	repo.identities["victim-1"] = &linkableUser{ID: "victim-1", Email: "victim@corp.example"}
	return repo
}

// TestOIDCLinkingRequiresVerifiedEmail is the account-takeover test.
//
// reconcileIdentity linked a federated login to an existing local account
// whenever the email claim matched, without ever consulting email_verified.
// Any identity provider that lets a user type an arbitrary address --
// self-registration at a public IdP, a permissive enterprise directory --
// therefore granted a login as any local user with that address. The attacker
// needs no credential, no prior access, and no interaction with the victim.
func TestOIDCLinkingRequiresVerifiedEmail(t *testing.T) {
	cases := []struct {
		name   string
		claims map[string]any
	}{
		{
			name:   "explicitly unverified",
			claims: map[string]any{"sub": "attacker", "email": "victim@corp.example", "email_verified": false},
		},
		{
			name:   "claim absent",
			claims: map[string]any{"sub": "attacker", "email": "victim@corp.example"},
		},
		{
			// Some providers send the claim as a string. Anything that is not
			// a true boolean must count as unverified rather than as truthy.
			name:   "non-boolean claim",
			claims: map[string]any{"sub": "attacker", "email": "victim@corp.example", "email_verified": "false"},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			manager := newLinkingManager(&linkingRepo{mockRepo: seedVictim(t)})

			got, err := manager.reconcileIdentity(context.Background(), "google", tc.claims)
			if err != nil {
				// Refusing outright is an acceptable outcome.
				return
			}
			if got == nil {
				return
			}
			if ident, ok := got.(*linkableUser); ok && ident.ID == "victim-1" {
				t.Errorf("an unverified %q claim linked the attacker to the victim's account",
					"email_verified")
			}
		})
	}
}

// TestOIDCLinkingAcceptsVerifiedEmail keeps the feature working: a provider
// that vouches for the address still links, which is the whole point of
// federated login.
func TestOIDCLinkingAcceptsVerifiedEmail(t *testing.T) {
	manager := newLinkingManager(&linkingRepo{mockRepo: seedVictim(t)})

	claims := map[string]any{
		"sub": "google-user-1", "email": "victim@corp.example", "email_verified": true,
	}
	got, err := manager.reconcileIdentity(context.Background(), "google", claims)
	if err != nil {
		t.Fatalf("reconcileIdentity: %v", err)
	}
	ident, ok := got.(*linkableUser)
	if !ok {
		t.Fatalf("got %T, want *linkableUser", got)
	}
	if ident.ID != "victim-1" {
		t.Errorf("a verified email did not link to the existing account: got %q", ident.ID)
	}
}

// TestOIDCMapClaimsEscapesTheEmail covers traits injection.
//
// The default mapper built its JSON with fmt.Sprintf, so an email claim
// containing a quote closed the string and appended sibling keys. The claim
// comes from a federated provider and is attacker-influenced, which made the
// traits document writable by whoever controlled the address.
func TestOIDCMapClaimsEscapesTheEmail(t *testing.T) {
	manager := newLinkingManager(&linkingRepo{mockRepo: seedVictim(t)})

	hostile := `x@example.test", "admin": true, "role": "superuser`
	traits := manager.mapClaims(map[string]any{"email": hostile})

	var decoded map[string]any
	if err := json.Unmarshal(traits, &decoded); err != nil {
		t.Fatalf("mapClaims produced invalid JSON (%s): %v", traits, err)
	}
	for _, injected := range []string{"admin", "role"} {
		if _, present := decoded[injected]; present {
			t.Errorf("the email claim injected the key %q into traits: %s", injected, traits)
		}
	}
	if decoded["email"] != hostile {
		t.Errorf("email = %v, want the value preserved verbatim", decoded["email"])
	}
}
