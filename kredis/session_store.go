package kredis

import (
	"context"
	"fmt"
	"strconv"
	"time"

	"github.com/getkayan/kayan/core/identity"
	"github.com/redis/go-redis/v9"
)

// sessionStorage mirrors domain.SessionStorage to avoid exporting the check.
type sessionStorage interface {
	CreateSession(s *identity.Session) error
	GetSession(id any) (*identity.Session, error)
	GetSessionByRefreshToken(token string) (*identity.Session, error)
	DeleteSession(id any) error
}

var _ sessionStorage = (*RedisSessionStore)(nil)

// RedisSessionStore implements domain.SessionStorage using Redis.
type RedisSessionStore struct {
	client *redis.Client
	prefix string
	ttl    time.Duration
}

// SessionStoreOption configures a RedisSessionStore.
type SessionStoreOption func(*RedisSessionStore)

// WithSessionPrefix sets the key prefix for session data.
func WithSessionPrefix(prefix string) SessionStoreOption {
	return func(s *RedisSessionStore) { s.prefix = prefix }
}

// WithSessionTTL sets the TTL for session keys.
func WithSessionTTL(ttl time.Duration) SessionStoreOption {
	return func(s *RedisSessionStore) { s.ttl = ttl }
}

// NewRedisSessionStore creates a new Redis-backed session store.
func NewRedisSessionStore(client *redis.Client, opts ...SessionStoreOption) *RedisSessionStore {
	s := &RedisSessionStore{
		client: client,
		prefix: "kayan:session:",
		ttl:    24 * time.Hour,
	}
	for _, opt := range opts {
		opt(s)
	}
	return s
}

func (s *RedisSessionStore) sessionKey(id string) string {
	return s.prefix + id
}

func (s *RedisSessionStore) refreshKey(token string) string {
	return s.prefix + "refresh:" + token
}

// CreateSession stores a session in Redis as a hash with a refresh token mapping.
func (s *RedisSessionStore) CreateSession(sess *identity.Session) error {
	ctx := context.Background()
	key := s.sessionKey(sess.ID)

	fields := map[string]any{
		"id":                 sess.ID,
		"identity_id":        sess.IdentityID,
		"refresh_token":      sess.RefreshToken,
		"expires_at":         sess.ExpiresAt.Unix(),
		"refresh_expires_at": sess.RefreshExpiresAt.Unix(),
		"issued_at":          sess.IssuedAt.Unix(),
		"active":             strconv.FormatBool(sess.Active),
	}

	pipe := s.client.Pipeline()
	pipe.HSet(ctx, key, fields)
	pipe.Expire(ctx, key, s.ttl)

	if sess.RefreshToken != "" {
		rk := s.refreshKey(sess.RefreshToken)
		pipe.Set(ctx, rk, sess.ID, s.ttl)
	}

	_, err := pipe.Exec(ctx)
	if err != nil {
		return fmt.Errorf("kredis: create session: %w", err)
	}
	return nil
}

// GetSession retrieves a session by its ID.
func (s *RedisSessionStore) GetSession(id any) (*identity.Session, error) {
	ctx := context.Background()
	key := s.sessionKey(fmt.Sprintf("%v", id))

	data, err := s.client.HGetAll(ctx, key).Result()
	if err != nil {
		return nil, fmt.Errorf("kredis: get session: %w", err)
	}
	if len(data) == 0 {
		return nil, fmt.Errorf("kredis: session not found")
	}

	return parseSession(data)
}

// GetSessionByRefreshToken looks up a session by its refresh token.
func (s *RedisSessionStore) GetSessionByRefreshToken(token string) (*identity.Session, error) {
	ctx := context.Background()
	rk := s.refreshKey(token)

	sessionID, err := s.client.Get(ctx, rk).Result()
	if err == redis.Nil {
		return nil, fmt.Errorf("kredis: session not found for refresh token")
	}
	if err != nil {
		return nil, fmt.Errorf("kredis: get refresh token: %w", err)
	}

	return s.GetSession(sessionID)
}

// DeleteSession removes a session and its refresh token mapping.
func (s *RedisSessionStore) DeleteSession(id any) error {
	ctx := context.Background()
	key := s.sessionKey(fmt.Sprintf("%v", id))

	// Get refresh token before deleting so we can clean up the mapping
	rt, _ := s.client.HGet(ctx, key, "refresh_token").Result()

	pipe := s.client.Pipeline()
	pipe.Del(ctx, key)
	if rt != "" {
		pipe.Del(ctx, s.refreshKey(rt))
	}

	_, err := pipe.Exec(ctx)
	if err != nil {
		return fmt.Errorf("kredis: delete session: %w", err)
	}
	return nil
}

func parseSession(data map[string]string) (*identity.Session, error) {
	expiresAt, _ := strconv.ParseInt(data["expires_at"], 10, 64)
	refreshExpiresAt, _ := strconv.ParseInt(data["refresh_expires_at"], 10, 64)
	issuedAt, _ := strconv.ParseInt(data["issued_at"], 10, 64)
	active, _ := strconv.ParseBool(data["active"])

	return &identity.Session{
		ID:               data["id"],
		IdentityID:       data["identity_id"],
		RefreshToken:     data["refresh_token"],
		ExpiresAt:        time.Unix(expiresAt, 0),
		RefreshExpiresAt: time.Unix(refreshExpiresAt, 0),
		IssuedAt:         time.Unix(issuedAt, 0),
		Active:           active,
	}, nil
}
