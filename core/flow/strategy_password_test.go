package flow

import (
	"context"
	"testing"

	"github.com/getkayan/kayan/core/domain"
	"github.com/getkayan/kayan/core/identity"
	"github.com/google/uuid"
)

// countingHasher records how much hashing work each authentication attempt
// costs. Asserting on wall-clock would be flaky; the call count is the thing
// the timing gap is actually made of.
type countingHasher struct {
	domain.Hasher
	compares int
}

func (h *countingHasher) Hash(password string) (string, error) {
	return h.Hasher.Hash(password)
}

func (h *countingHasher) Compare(password, hash string) bool {
	h.compares++
	return h.Hasher.Compare(password, hash)
}

// TestPasswordAuthDoesNotLeakIdentifierExistenceByTiming covers a user
// enumeration oracle: an attempt against an unknown identifier returned before
// any hashing happened, while an attempt against a known one paid for a full
// bcrypt compare. Identical error messages do not help when the two responses
// differ by ~250ms at the default cost.
//
// Both paths must do the same amount of hash work.
func TestPasswordAuthDoesNotLeakIdentifierExistenceByTiming(t *testing.T) {
	ctx := context.Background()

	const knownEmail = "real@example.com"

	for _, tc := range []struct {
		name    string
		factory func() any
		setup   func(*PasswordStrategy)
	}{
		{
			name:    "classic credential lookup",
			factory: func() any { return &identity.Identity{} },
			setup: func(s *PasswordStrategy) {
				traits := identity.JSON(`{"email":"` + knownEmail + `"}`)
				if _, err := s.Register(ctx, traits, "password123"); err != nil {
					t.Fatalf("Register: %v", err)
				}
			},
		},
		{
			// The BYOS path queries the identity table directly rather than a
			// credentials table, so it returns from a different branch and
			// needs its own coverage.
			name:    "byos field mapping",
			factory: func() any { return &customIdentity{} },
			setup: func(s *PasswordStrategy) {
				s.MapFields([]string{"Email"}, "PasswordHash")
				traits := identity.JSON(`{"Email":"` + knownEmail + `"}`)
				if _, err := s.Register(ctx, traits, "password123"); err != nil {
					t.Fatalf("Register: %v", err)
				}
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			repo := &mockRepo{
				identities: make(map[string]any),
				creds:      make(map[string]*identity.Credential),
			}
			hasher := &countingHasher{Hasher: NewBcryptHasher(4)}
			strategy := NewPasswordStrategy(repo, hasher, "email", tc.factory)
			strategy.SetIDGenerator(func() any { return uuid.New() })
			tc.setup(strategy)

			// Warm the dummy hash so the one-off cost of computing it does not
			// land inside a measured attempt.
			_, _ = strategy.Authenticate(ctx, "warm@example.com", "whatever1")

			hasher.compares = 0
			if _, err := strategy.Authenticate(ctx, knownEmail, "wrongpassword"); err == nil {
				t.Fatal("a wrong password was accepted")
			}
			known := hasher.compares

			hasher.compares = 0
			if _, err := strategy.Authenticate(ctx, "nobody@example.com", "wrongpassword"); err == nil {
				t.Fatal("an unknown identifier was accepted")
			}
			unknown := hasher.compares

			if known == 0 {
				t.Fatal("the known-identifier path did no hashing; the test proves nothing")
			}
			if unknown != known {
				t.Errorf("hash comparisons: known identifier %d, unknown identifier %d — "+
					"the difference is observable as response latency", known, unknown)
			}
		})
	}
}
