package redisstore

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/getkayan/kayan/core/session"
	"github.com/redis/go-redis/v9"
)

const maxSSORetries = 16

// RedisSSOStore persists cross-application sessions in Redis. Transactions
// make membership changes atomic across application processes.
type RedisSSOStore struct {
	client redis.UniversalClient
	prefix string
}

// NewRedisSSOStore creates an optional Redis-backed session.SSOStore.
func NewRedisSSOStore(client redis.UniversalClient, prefix string) *RedisSSOStore {
	if prefix == "" {
		prefix = "kayan:sso:"
	} else if !strings.HasSuffix(prefix, ":") {
		prefix += ":"
	}
	return &RedisSSOStore{client: client, prefix: prefix}
}

func (s *RedisSSOStore) sessionKey(id string) string  { return s.prefix + "session:" + id }
func (s *RedisSSOStore) identityKey(id string) string { return s.prefix + "identity:" + id }

func (s *RedisSSOStore) CreateOrJoinSSOSession(ctx context.Context, candidate *session.SSOSession) (*session.SSOSession, error) {
	identityKey := s.identityKey(candidate.IdentityID)
	for attempt := 0; attempt < maxSSORetries; attempt++ {
		observedID, err := s.client.Get(ctx, identityKey).Result()
		if err != nil && !errors.Is(err, redis.Nil) {
			return nil, fmt.Errorf("redis sso: read identity index: %w", err)
		}
		keys := []string{identityKey}
		if observedID != "" {
			keys = append(keys, s.sessionKey(observedID))
		}
		var result *session.SSOSession
		err = s.client.Watch(ctx, func(tx *redis.Tx) error {
			currentID, getErr := tx.Get(ctx, identityKey).Result()
			if errors.Is(getErr, redis.Nil) {
				currentID = ""
			} else if getErr != nil {
				return getErr
			}
			if currentID != observedID {
				return redis.TxFailedErr
			}

			if currentID == "" {
				if err := validateTTL(candidate.ExpiresAt); err != nil {
					return err
				}
				data, err := json.Marshal(candidate)
				if err != nil {
					return err
				}
				_, err = tx.TxPipelined(ctx, func(pipe redis.Pipeliner) error {
					pipe.Set(ctx, s.sessionKey(candidate.ID), data, time.Until(candidate.ExpiresAt))
					pipe.Set(ctx, identityKey, candidate.ID, time.Until(candidate.ExpiresAt))
					return nil
				})
				result = cloneSession(candidate)
				return err
			}

			existing, err := readSSO(ctx, tx, s.sessionKey(currentID))
			if errors.Is(err, session.ErrSSONotFound) || (err == nil && (!existing.Active || !existing.ExpiresAt.After(candidate.CreatedAt))) {
				if err := s.replaceExpired(ctx, tx, identityKey, existing, candidate); err != nil {
					return err
				}
				result = cloneSession(candidate)
				return nil
			}
			if err != nil {
				return err
			}
			app := candidate.AppSessions[0]
			for _, current := range existing.AppSessions {
				if current.AppID == app.AppID {
					result = existing
					return nil
				}
			}
			existing.AppSessions = append(existing.AppSessions, app)
			if err := writeSSO(ctx, tx, s.sessionKey(existing.ID), existing); err != nil {
				return err
			}
			result = existing
			return nil
		}, keys...)
		if errors.Is(err, redis.TxFailedErr) {
			continue
		}
		if err != nil {
			return nil, fmt.Errorf("redis sso: create or join: %w", err)
		}
		return result, nil
	}
	return nil, errors.New("redis sso: transaction retry limit exceeded")
}

func (s *RedisSSOStore) replaceExpired(ctx context.Context, tx *redis.Tx, identityKey string, existing, candidate *session.SSOSession) error {
	if err := validateTTL(candidate.ExpiresAt); err != nil {
		return err
	}
	data, err := json.Marshal(candidate)
	if err != nil {
		return err
	}
	_, err = tx.TxPipelined(ctx, func(pipe redis.Pipeliner) error {
		if existing != nil {
			pipe.Del(ctx, s.sessionKey(existing.ID))
		}
		pipe.Set(ctx, s.sessionKey(candidate.ID), data, time.Until(candidate.ExpiresAt))
		pipe.Set(ctx, identityKey, candidate.ID, time.Until(candidate.ExpiresAt))
		return nil
	})
	return err
}

func (s *RedisSSOStore) GetSSOSession(ctx context.Context, id string) (*session.SSOSession, error) {
	return readSSO(ctx, s.client, s.sessionKey(id))
}

func (s *RedisSSOStore) GetSSOSessionByIdentity(ctx context.Context, identityID string) (*session.SSOSession, error) {
	id, err := s.client.Get(ctx, s.identityKey(identityID)).Result()
	if errors.Is(err, redis.Nil) {
		return nil, session.ErrSSONotFound
	}
	if err != nil {
		return nil, fmt.Errorf("redis sso: read identity index: %w", err)
	}
	return s.GetSSOSession(ctx, id)
}

func (s *RedisSSOStore) JoinSSOSession(ctx context.Context, id string, app session.AppSession) (*session.AppSession, error) {
	var result *session.AppSession
	err := s.mutate(ctx, id, func(current *session.SSOSession) error {
		if !current.Active {
			return session.ErrSSOInactive
		}
		if !app.CreatedAt.Before(current.ExpiresAt) {
			return session.ErrSSOExpired
		}
		for _, existing := range current.AppSessions {
			if existing.AppID == app.AppID {
				copy := existing
				result = &copy
				return nil
			}
		}
		current.AppSessions = append(current.AppSessions, app)
		copy := app
		result = &copy
		return nil
	})
	return result, err
}

func (s *RedisSSOStore) LeaveSSOSession(ctx context.Context, id, appID string) error {
	return s.mutate(ctx, id, func(current *session.SSOSession) error {
		apps := make([]session.AppSession, 0, len(current.AppSessions))
		found := false
		for _, app := range current.AppSessions {
			if app.AppID == appID {
				found = true
				continue
			}
			apps = append(apps, app)
		}
		if !found {
			return session.ErrSSOAppNotFound
		}
		current.AppSessions = apps
		if len(apps) == 0 {
			current.Active = false
		}
		return nil
	})
}

func (s *RedisSSOStore) DeactivateSSOSession(ctx context.Context, id string) ([]session.AppSession, error) {
	var apps []session.AppSession
	err := s.mutate(ctx, id, func(current *session.SSOSession) error {
		current.Active = false
		apps = append([]session.AppSession(nil), current.AppSessions...)
		return nil
	})
	return apps, err
}

func (s *RedisSSOStore) DeleteSSOSession(ctx context.Context, id string) error {
	current, err := s.GetSSOSession(ctx, id)
	if err != nil {
		return err
	}
	_, err = s.client.TxPipelined(ctx, func(pipe redis.Pipeliner) error {
		pipe.Del(ctx, s.sessionKey(id))
		pipe.Del(ctx, s.identityKey(current.IdentityID))
		return nil
	})
	return err
}

func (s *RedisSSOStore) mutate(ctx context.Context, id string, mutate func(*session.SSOSession) error) error {
	key := s.sessionKey(id)
	for attempt := 0; attempt < maxSSORetries; attempt++ {
		err := s.client.Watch(ctx, func(tx *redis.Tx) error {
			current, err := readSSO(ctx, tx, key)
			if err != nil {
				return err
			}
			if err := mutate(current); err != nil {
				return err
			}
			return writeSSO(ctx, tx, key, current)
		}, key)
		if errors.Is(err, redis.TxFailedErr) {
			continue
		}
		if err != nil {
			return fmt.Errorf("redis sso: mutate: %w", err)
		}
		return nil
	}
	return errors.New("redis sso: transaction retry limit exceeded")
}

type redisGetter interface {
	Get(ctx context.Context, key string) *redis.StringCmd
}

func readSSO(ctx context.Context, client redisGetter, key string) (*session.SSOSession, error) {
	data, err := client.Get(ctx, key).Bytes()
	if errors.Is(err, redis.Nil) {
		return nil, session.ErrSSONotFound
	}
	if err != nil {
		return nil, err
	}
	var value session.SSOSession
	if err := json.Unmarshal(data, &value); err != nil {
		return nil, fmt.Errorf("redis sso: decode session: %w", err)
	}
	return &value, nil
}

func writeSSO(ctx context.Context, tx *redis.Tx, key string, value *session.SSOSession) error {
	if err := validateTTL(value.ExpiresAt); err != nil {
		return err
	}
	data, err := json.Marshal(value)
	if err != nil {
		return err
	}
	_, err = tx.TxPipelined(ctx, func(pipe redis.Pipeliner) error {
		pipe.Set(ctx, key, data, time.Until(value.ExpiresAt))
		return nil
	})
	return err
}

func validateTTL(expiresAt time.Time) error {
	if time.Until(expiresAt) <= 0 {
		return session.ErrSSOExpired
	}
	return nil
}

func cloneSession(value *session.SSOSession) *session.SSOSession {
	clone := *value
	clone.AppSessions = append([]session.AppSession(nil), value.AppSessions...)
	return &clone
}

var _ session.SSOStore = (*RedisSSOStore)(nil)
