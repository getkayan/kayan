package oauth2

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/getkayan/kayan/core/domain"
	"golang.org/x/crypto/bcrypt"
)

// --- test doubles ---

// securityStore is an in-memory ClientStore, AuthCodeStore, and
// RefreshTokenFamilyStore.
type securityStore struct {
	mu       sync.Mutex
	clients  map[string]*Client
	codes    map[string]*AuthCode
	refresh  map[string]*RefreshToken
	families map[string][]string
}

func newSecurityStore() *securityStore {
	return &securityStore{
		clients:  make(map[string]*Client),
		codes:    make(map[string]*AuthCode),
		refresh:  make(map[string]*RefreshToken),
		families: make(map[string][]string),
	}
}

func (s *securityStore) GetClient(_ context.Context, id string) (*Client, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if c, ok := s.clients[id]; ok {
		return c, nil
	}
	return nil, errors.New("client not found")
}

func (s *securityStore) CreateClient(_ context.Context, c *Client) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.clients[c.ID] = c
	return nil
}

func (s *securityStore) DeleteClient(_ context.Context, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.clients, id)
	return nil
}

func (s *securityStore) SaveAuthCode(_ context.Context, c *AuthCode) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.codes[c.Code] = c
	return nil
}

func (s *securityStore) GetAuthCode(_ context.Context, code string) (*AuthCode, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if c, ok := s.codes[code]; ok {
		return c, nil
	}
	return nil, errors.New("code not found")
}

func (s *securityStore) DeleteAuthCode(_ context.Context, code string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.codes, code)
	return nil
}

func (s *securityStore) SaveRefreshToken(_ context.Context, t *RefreshToken) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.refresh[t.Token] = t
	s.families[t.FamilyID] = append(s.families[t.FamilyID], t.Token)
	return nil
}

func (s *securityStore) GetRefreshToken(_ context.Context, token string) (*RefreshToken, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if t, ok := s.refresh[token]; ok {
		return t, nil
	}
	return nil, errors.New("refresh token not found")
}

func (s *securityStore) DeleteRefreshToken(_ context.Context, token string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.refresh, token)
	return nil
}

func (s *securityStore) MarkRefreshTokenUsed(_ context.Context, token string, usedAt time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	t, ok := s.refresh[token]
	if !ok {
		return errors.New("refresh token not found")
	}
	t.UsedAt = &usedAt
	return nil
}

func (s *securityStore) RevokeFamily(_ context.Context, familyID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, token := range s.families[familyID] {
		delete(s.refresh, token)
	}
	delete(s.families, familyID)
	return nil
}

// --- helpers ---

const (
	testClientID     = "client-1"
	testClientSecret = "correct-client-secret"
	testRedirectURI  = "https://app.example.test/callback"
)

func newSecureProvider(t testing.TB, opts ...ProviderOption) (*Provider, *securityStore) {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	store := newSecurityStore()
	hasher := domain.NewBcryptHasher(bcrypt.MinCost)
	hash, err := hasher.Hash(testClientSecret)
	if err != nil {
		t.Fatalf("hash secret: %v", err)
	}
	store.clients[testClientID] = &Client{
		ID:           testClientID,
		SecretHash:   hash,
		RedirectURIs: []string{testRedirectURI},
	}

	opts = append([]ProviderOption{WithClientSecretHasher(hasher)}, opts...)
	provider := NewProvider(store, store, store, "https://issuer.example.test", key, "kid-1", opts...)
	return provider, store
}

func challengeFor(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// --- redirect_uri allowlist ---

// TestRedirectURIAllowlist is the open-redirector corpus. Every entry is a
// real technique for making a URI look like the registered one.
func TestRedirectURIAllowlist(t *testing.T) {
	ctx := context.Background()
	provider, _ := newSecureProvider(t)

	hostile := []string{
		"https://evil.example.test/callback",
		"https://app.example.test.evil.test/callback",    // suffix on the host
		"https://app.example.test@evil.test/callback",    // userinfo confusion
		"https://evil.test/?x=https://app.example.test/", // registered URI in a parameter
		"https://app.example.test/callback/../../evil",   // path traversal
		"https://app.example.test/callback/extra",        // prefix of a longer path
		"https://app.example.test:8443/callback",         // different port
		"http://app.example.test/callback",               // downgraded scheme
		"https://app.example.test/callback#evil",         // fragment
		"https://app.example.test/callback?next=//evil",  // open redirect in a query
		"https://аpp.example.test/callback",              // Cyrillic 'а' homoglyph
		"https://app.example.test/Callback",              // case differs
		"https://app.example.test/callback/",             // trailing slash
		"",                                               // empty
	}

	for _, uri := range hostile {
		t.Run(uri, func(t *testing.T) {
			_, err := provider.GenerateAuthCode(ctx, testClientID, "user-1", uri,
				[]string{"openid"}, challengeFor("v"), challengeMethodS256)
			if err == nil {
				t.Fatalf("unregistered redirect_uri accepted: %q", uri)
			}
			if !errors.Is(err, ErrInvalidRequest) {
				t.Errorf("error = %v, want ErrInvalidRequest", err)
			}
		})
	}

	// The registered URI must still work.
	if _, err := provider.GenerateAuthCode(ctx, testClientID, "user-1", testRedirectURI,
		[]string{"openid"}, challengeFor("v"), challengeMethodS256); err != nil {
		t.Fatalf("the registered redirect_uri was rejected: %v", err)
	}
}

// --- client authentication ---

// TestClientAuthenticationIsMandatory covers the case where omitting the
// secret previously skipped verification entirely.
func TestClientAuthenticationIsMandatory(t *testing.T) {
	ctx := context.Background()

	t.Run("empty secret is refused", func(t *testing.T) {
		provider, _ := newSecureProvider(t)
		if _, err := provider.ValidateClient(ctx, testClientID, ""); !errors.Is(err, ErrInvalidClient) {
			t.Fatalf("error = %v, want ErrInvalidClient for an empty secret", err)
		}
	})

	t.Run("wrong secret is refused", func(t *testing.T) {
		provider, _ := newSecureProvider(t)
		if _, err := provider.ValidateClient(ctx, testClientID, "wrong"); !errors.Is(err, ErrInvalidClient) {
			t.Fatalf("error = %v, want ErrInvalidClient", err)
		}
	})

	t.Run("correct secret is accepted", func(t *testing.T) {
		provider, _ := newSecureProvider(t)
		if _, err := provider.ValidateClient(ctx, testClientID, testClientSecret); err != nil {
			t.Fatalf("the correct secret was rejected: %v", err)
		}
	})

	t.Run("exchange refuses an empty secret", func(t *testing.T) {
		provider, _ := newSecureProvider(t)
		const verifier = "exchange-verifier"
		code, err := provider.GenerateAuthCode(ctx, testClientID, "user-1", testRedirectURI,
			[]string{"openid"}, challengeFor(verifier), challengeMethodS256)
		if err != nil {
			t.Fatalf("GenerateAuthCode: %v", err)
		}
		if _, err := provider.Exchange(ctx, code, testClientID, "", testRedirectURI, verifier); !errors.Is(err, ErrInvalidClient) {
			t.Fatalf("error = %v, want ErrInvalidClient; an empty secret must not authenticate", err)
		}
	})

	t.Run("confidential client with no stored hash fails closed", func(t *testing.T) {
		provider, store := newSecureProvider(t)
		store.clients["broken"] = &Client{ID: "broken", RedirectURIs: []string{testRedirectURI}}

		if _, err := provider.ValidateClient(ctx, "broken", ""); !errors.Is(err, ErrInvalidClient) {
			t.Errorf("error = %v, want ErrInvalidClient", err)
		}
		if _, err := provider.ValidateClient(ctx, "broken", "anything"); !errors.Is(err, ErrInvalidClient) {
			t.Errorf("error = %v, want ErrInvalidClient", err)
		}
	})
}

// TestClientSecretIsNotStoredInPlaintext proves the secret never reaches the
// Client struct, so a store disclosure does not leak credentials.
func TestClientSecretIsNotStoredInPlaintext(t *testing.T) {
	_, store := newSecureProvider(t)

	client := store.clients[testClientID]
	if client.SecretHash == testClientSecret {
		t.Fatal("the client secret is stored in plaintext")
	}
	if !bcryptLooking(client.SecretHash) {
		t.Errorf("SecretHash = %q, want a bcrypt hash", client.SecretHash)
	}
}

func bcryptLooking(s string) bool {
	return len(s) > 4 && s[0] == '$' && s[1] == '2'
}

// TestUnknownClientIsIndistinguishable proves the error does not reveal
// whether a client ID exists, which would let an attacker enumerate them.
func TestUnknownClientIsIndistinguishable(t *testing.T) {
	ctx := context.Background()
	provider, _ := newSecureProvider(t)

	_, unknownErr := provider.ValidateClient(ctx, "no-such-client", "whatever")
	_, wrongErr := provider.ValidateClient(ctx, testClientID, "wrong-secret")

	if unknownErr == nil || wrongErr == nil {
		t.Fatal("expected both lookups to fail")
	}

	var a, b *Error
	if !errors.As(unknownErr, &a) || !errors.As(wrongErr, &b) {
		t.Fatal("expected protocol errors")
	}
	if a.Code != b.Code || a.Description != b.Description {
		t.Errorf("unknown client reports %q/%q but a wrong secret reports %q/%q; the two must be indistinguishable",
			a.Code, a.Description, b.Code, b.Description)
	}
}

// --- PKCE ---

func TestPKCEIsMandatoryByDefault(t *testing.T) {
	ctx := context.Background()
	provider, _ := newSecureProvider(t)

	_, err := provider.GenerateAuthCode(ctx, testClientID, "user-1", testRedirectURI,
		[]string{"openid"}, "", "")
	if !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("error = %v, want ErrInvalidRequest; a code without a challenge must be refused", err)
	}
}

// TestPKCECannotBeDowngradedToPlain covers the downgrade where an omitted
// method was treated as "plain", making the challenge equal to the verifier.
func TestPKCECannotBeDowngradedToPlain(t *testing.T) {
	ctx := context.Background()
	provider, _ := newSecureProvider(t)

	t.Run("plain is refused at issuance", func(t *testing.T) {
		_, err := provider.GenerateAuthCode(ctx, testClientID, "user-1", testRedirectURI,
			[]string{"openid"}, "some-challenge", challengeMethodPlain)
		if !errors.Is(err, ErrInvalidRequest) {
			t.Fatalf("error = %v, want ErrInvalidRequest", err)
		}
	})

	t.Run("an empty method is refused at issuance", func(t *testing.T) {
		_, err := provider.GenerateAuthCode(ctx, testClientID, "user-1", testRedirectURI,
			[]string{"openid"}, "some-challenge", "")
		if !errors.Is(err, ErrInvalidRequest) {
			t.Fatalf("error = %v, want ErrInvalidRequest", err)
		}
	})

	t.Run("a stored plain challenge does not verify", func(t *testing.T) {
		// Simulate a code stored before this rule existed: the challenge and
		// verifier are identical and the method is empty.
		const secret = "attacker-chosen-value"
		store := newSecurityStore()
		hasher := domain.NewBcryptHasher(bcrypt.MinCost)
		hash, _ := hasher.Hash(testClientSecret)
		store.clients[testClientID] = &Client{ID: testClientID, SecretHash: hash, RedirectURIs: []string{testRedirectURI}}
		store.codes["legacy"] = &AuthCode{
			Code: "legacy", ClientID: testClientID, IdentityID: "user-1",
			RedirectURI: testRedirectURI, CodeChallenge: secret, CodeChallengeMethod: "",
			ExpiresAt: time.Now().Add(time.Minute),
		}

		key, _ := rsa.GenerateKey(rand.Reader, 2048)
		p := NewProvider(store, store, store, "https://issuer.example.test", key, "kid-1",
			WithClientSecretHasher(hasher))

		_, err := p.Exchange(ctx, "legacy", testClientID, testClientSecret, testRedirectURI, secret)
		if !errors.Is(err, ErrInvalidGrant) {
			t.Fatalf("error = %v, want ErrInvalidGrant; an empty method must not verify as plain", err)
		}
	})
}

func TestPKCEPlainWorksWhenExplicitlyEnabled(t *testing.T) {
	ctx := context.Background()
	provider, _ := newSecureProvider(t, WithAllowPlainCodeChallenge(true))

	const verifier = "plain-verifier-value"
	code, err := provider.GenerateAuthCode(ctx, testClientID, "user-1", testRedirectURI,
		[]string{"openid"}, verifier, challengeMethodPlain)
	if err != nil {
		t.Fatalf("GenerateAuthCode: %v", err)
	}

	if _, err := provider.Exchange(ctx, code, testClientID, testClientSecret, testRedirectURI, verifier); err != nil {
		t.Fatalf("Exchange with an explicitly enabled plain challenge failed: %v", err)
	}
}

// --- authorization code handling ---

func TestAuthCodeIsSingleUse(t *testing.T) {
	ctx := context.Background()
	provider, _ := newSecureProvider(t)

	const verifier = "single-use-verifier"
	code, err := provider.GenerateAuthCode(ctx, testClientID, "user-1", testRedirectURI,
		[]string{"openid"}, challengeFor(verifier), challengeMethodS256)
	if err != nil {
		t.Fatalf("GenerateAuthCode: %v", err)
	}

	if _, err := provider.Exchange(ctx, code, testClientID, testClientSecret, testRedirectURI, verifier); err != nil {
		t.Fatalf("first exchange: %v", err)
	}
	if _, err := provider.Exchange(ctx, code, testClientID, testClientSecret, testRedirectURI, verifier); !errors.Is(err, ErrInvalidGrant) {
		t.Fatalf("error = %v, want ErrInvalidGrant; an authorization code must be single-use", err)
	}
}

// TestAuthCodeIsConsumedOnFailedExchange proves a failed attempt still burns
// the code, so an attacker cannot retry other parameters against it.
func TestAuthCodeIsConsumedOnFailedExchange(t *testing.T) {
	ctx := context.Background()
	provider, _ := newSecureProvider(t)

	const verifier = "burn-verifier"
	code, err := provider.GenerateAuthCode(ctx, testClientID, "user-1", testRedirectURI,
		[]string{"openid"}, challengeFor(verifier), challengeMethodS256)
	if err != nil {
		t.Fatalf("GenerateAuthCode: %v", err)
	}

	if _, err := provider.Exchange(ctx, code, testClientID, testClientSecret, testRedirectURI, "wrong-verifier"); err == nil {
		t.Fatal("exchange with a wrong verifier succeeded")
	}
	if _, err := provider.Exchange(ctx, code, testClientID, testClientSecret, testRedirectURI, verifier); !errors.Is(err, ErrInvalidGrant) {
		t.Fatalf("error = %v, want ErrInvalidGrant; the code should have been consumed", err)
	}
}

func TestAuthCodeIsBoundToItsClient(t *testing.T) {
	ctx := context.Background()
	provider, store := newSecureProvider(t)

	hasher := domain.NewBcryptHasher(bcrypt.MinCost)
	otherHash, _ := hasher.Hash("other-secret")
	store.clients["client-2"] = &Client{
		ID: "client-2", SecretHash: otherHash, RedirectURIs: []string{testRedirectURI},
	}

	const verifier = "binding-verifier"
	code, err := provider.GenerateAuthCode(ctx, testClientID, "user-1", testRedirectURI,
		[]string{"openid"}, challengeFor(verifier), challengeMethodS256)
	if err != nil {
		t.Fatalf("GenerateAuthCode: %v", err)
	}

	// A different, correctly authenticated client must not redeem it.
	_, err = provider.Exchange(ctx, code, "client-2", "other-secret", testRedirectURI, verifier)
	if !errors.Is(err, ErrInvalidGrant) {
		t.Fatalf("error = %v, want ErrInvalidGrant; a code must be bound to the client it was issued to", err)
	}
}

// --- refresh token reuse detection ---

// TestRefreshTokenReuseRevokesFamily is the theft scenario: a stolen refresh
// token is redeemed by both the attacker and the legitimate client, and the
// second redemption must invalidate the whole chain.
func TestRefreshTokenReuseRevokesFamily(t *testing.T) {
	ctx := context.Background()
	provider, _ := newSecureProvider(t)

	const verifier = "reuse-verifier"
	code, err := provider.GenerateAuthCode(ctx, testClientID, "user-1", testRedirectURI,
		[]string{"openid"}, challengeFor(verifier), challengeMethodS256)
	if err != nil {
		t.Fatalf("GenerateAuthCode: %v", err)
	}

	tokens, err := provider.Exchange(ctx, code, testClientID, testClientSecret, testRedirectURI, verifier)
	if err != nil {
		t.Fatalf("Exchange: %v", err)
	}
	stolen := tokens.RefreshToken

	// The attacker redeems the stolen token first and receives a new one.
	rotated, err := provider.Refresh(ctx, stolen, testClientID, testClientSecret)
	if err != nil {
		t.Fatalf("first refresh: %v", err)
	}

	// The legitimate client then presents the same token it still holds.
	if _, err := provider.Refresh(ctx, stolen, testClientID, testClientSecret); !errors.Is(err, ErrInvalidGrant) {
		t.Fatalf("error = %v, want ErrInvalidGrant on replay", err)
	}

	// The replay proved the chain is compromised, so the attacker's token must
	// be dead too.
	if _, err := provider.Refresh(ctx, rotated.RefreshToken, testClientID, testClientSecret); !errors.Is(err, ErrInvalidGrant) {
		t.Fatalf("error = %v; the rotated token must be revoked with its family", err)
	}
}

func TestRefreshTokenRotates(t *testing.T) {
	ctx := context.Background()
	provider, _ := newSecureProvider(t)

	const verifier = "rotate-verifier"
	code, err := provider.GenerateAuthCode(ctx, testClientID, "user-1", testRedirectURI,
		[]string{"openid"}, challengeFor(verifier), challengeMethodS256)
	if err != nil {
		t.Fatalf("GenerateAuthCode: %v", err)
	}
	tokens, err := provider.Exchange(ctx, code, testClientID, testClientSecret, testRedirectURI, verifier)
	if err != nil {
		t.Fatalf("Exchange: %v", err)
	}

	rotated, err := provider.Refresh(ctx, tokens.RefreshToken, testClientID, testClientSecret)
	if err != nil {
		t.Fatalf("Refresh: %v", err)
	}
	if rotated.RefreshToken == tokens.RefreshToken {
		t.Error("the refresh token was not rotated")
	}
}

func TestRefreshRequiresClientAuthentication(t *testing.T) {
	ctx := context.Background()
	provider, _ := newSecureProvider(t)

	const verifier = "auth-verifier"
	code, _ := provider.GenerateAuthCode(ctx, testClientID, "user-1", testRedirectURI,
		[]string{"openid"}, challengeFor(verifier), challengeMethodS256)
	tokens, err := provider.Exchange(ctx, code, testClientID, testClientSecret, testRedirectURI, verifier)
	if err != nil {
		t.Fatalf("Exchange: %v", err)
	}

	if _, err := provider.Refresh(ctx, tokens.RefreshToken, testClientID, ""); !errors.Is(err, ErrInvalidClient) {
		t.Fatalf("error = %v, want ErrInvalidClient; refresh must authenticate the client", err)
	}
}

// --- token entropy ---

// TestAuthCodesAreUnpredictable guards the reason TokenGenerator is separate
// from IDGenerator: a caller must not be able to make codes guessable.
func TestAuthCodesAreUnpredictable(t *testing.T) {
	ctx := context.Background()
	provider, _ := newSecureProvider(t)

	seen := make(map[string]bool)
	for range 100 {
		code, err := provider.GenerateAuthCode(ctx, testClientID, "user-1", testRedirectURI,
			[]string{"openid"}, challengeFor("v"), challengeMethodS256)
		if err != nil {
			t.Fatalf("GenerateAuthCode: %v", err)
		}
		if seen[code] {
			t.Fatalf("authorization code repeated: %q", code)
		}
		seen[code] = true

		// 32 bytes of base64url is 43 characters; anything much shorter means
		// the generator was replaced with something weak.
		if len(code) < 40 {
			t.Fatalf("authorization code is only %d characters: %q", len(code), code)
		}
	}
}
