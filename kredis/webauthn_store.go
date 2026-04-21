package kredis

import (
	"context"
	"fmt"
	"time"

	"github.com/getkayan/kayan/core/flow"
	"github.com/redis/go-redis/v9"
)

// Compile-time interface check.
var _ flow.WebAuthnSessionStore = (*RedisWebAuthnSessionStore)(nil)

// RedisWebAuthnSessionStore implements flow.WebAuthnSessionStore using Redis.
type RedisWebAuthnSessionStore struct {
	client *redis.Client
	prefix string
}

// NewRedisWebAuthnSessionStore creates a new Redis-based WebAuthn session store.
func NewRedisWebAuthnSessionStore(client *redis.Client, prefix string) *RedisWebAuthnSessionStore {
	if prefix == "" {
		prefix = "kayan:webauthn:session:"
	}
	return &RedisWebAuthnSessionStore{
		client: client,
		prefix: prefix,
	}
}

func (s *RedisWebAuthnSessionStore) key(sessionID string) string {
	return s.prefix + sessionID
}

func (s *RedisWebAuthnSessionStore) SaveSession(ctx context.Context, sessionID string, data *flow.WebAuthnSessionData) error {
	key := s.key(sessionID)
	ttl := time.Until(data.ExpiresAt)
	if ttl <= 0 {
		ttl = 5 * time.Minute
	}

	// Serialize the data
	fields := map[string]interface{}{
		"challenge":         data.Challenge,
		"user_id":           string(data.UserID),
		"user_verification": data.UserVerification,
		"expires_at":        data.ExpiresAt.Unix(),
	}

	pipe := s.client.Pipeline()
	pipe.HSet(ctx, key, fields)
	pipe.Expire(ctx, key, ttl)

	_, err := pipe.Exec(ctx)
	if err != nil {
		return fmt.Errorf("redis webauthn: save session failed: %w", err)
	}

	// Store allowed credential IDs if present
	if len(data.AllowedCredIDs) > 0 {
		credKey := key + ":creds"
		for i, cred := range data.AllowedCredIDs {
			s.client.HSet(ctx, credKey, fmt.Sprintf("%d", i), string(cred))
		}
		s.client.Expire(ctx, credKey, ttl)
	}

	return nil
}

func (s *RedisWebAuthnSessionStore) GetSession(ctx context.Context, sessionID string) (*flow.WebAuthnSessionData, error) {
	key := s.key(sessionID)

	result, err := s.client.HGetAll(ctx, key).Result()
	if err != nil {
		return nil, fmt.Errorf("redis webauthn: get session failed: %w", err)
	}
	if len(result) == 0 {
		return nil, fmt.Errorf("session not found")
	}

	var expiresAt int64
	fmt.Sscanf(result["expires_at"], "%d", &expiresAt)

	data := &flow.WebAuthnSessionData{
		Challenge:        result["challenge"],
		UserID:           []byte(result["user_id"]),
		UserVerification: result["user_verification"],
		ExpiresAt:        time.Unix(expiresAt, 0),
	}

	// Get allowed credential IDs if present
	credKey := key + ":creds"
	creds, err := s.client.HGetAll(ctx, credKey).Result()
	if err == nil && len(creds) > 0 {
		for i := 0; i < len(creds); i++ {
			if val, ok := creds[fmt.Sprintf("%d", i)]; ok {
				data.AllowedCredIDs = append(data.AllowedCredIDs, []byte(val))
			}
		}
	}

	return data, nil
}

func (s *RedisWebAuthnSessionStore) DeleteSession(ctx context.Context, sessionID string) error {
	key := s.key(sessionID)
	credKey := key + ":creds"

	pipe := s.client.Pipeline()
	pipe.Del(ctx, key)
	pipe.Del(ctx, credKey)
	_, err := pipe.Exec(ctx)

	if err != nil {
		return fmt.Errorf("redis webauthn: delete session failed: %w", err)
	}
	return nil
}
