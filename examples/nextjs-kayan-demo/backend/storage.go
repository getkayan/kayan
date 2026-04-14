package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sync"
	"time"

	"github.com/getkayan/kayan/core/audit"
	"github.com/getkayan/kayan/core/domain"
	"github.com/getkayan/kayan/core/identity"
)

var _ domain.IdentityStorage = (*InMemStorage)(nil)

type InMemStorage struct {
	mu         sync.RWMutex
	identities map[string]any
	creds      map[string]*identity.Credential
	sessions   map[string]*identity.Session
	tokens     map[string]any
}

func NewInMemStorage() *InMemStorage {
	return &InMemStorage{
		identities: make(map[string]any),
		creds:      make(map[string]*identity.Credential),
		sessions:   make(map[string]*identity.Session),
		tokens:     make(map[string]any),
	}
}

func (s *InMemStorage) CreateIdentity(ident any) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	fi, ok := ident.(interface{ GetID() any })
	if !ok {
		return errors.New("identity does not implement GetID")
	}
	s.identities[fmt.Sprintf("%v", fi.GetID())] = ident
	
	// Also index credentials
	if cs, ok := ident.(interface{ GetCredentials() []identity.Credential }); ok {
		for _, c := range cs.GetCredentials() {
			s.creds[c.Identifier+":"+c.Type] = &c
		}
	}
	return nil
}

func (s *InMemStorage) GetIdentity(factory func() any, id any) (any, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	ident, ok := s.identities[fmt.Sprintf("%v", id)]
	if !ok {
		return nil, errors.New("identity not found")
	}
	return ident, nil
}

func (s *InMemStorage) FindIdentity(factory func() any, filter map[string]any) (any, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	
	for _, ident := range s.identities {
		if traitSource, ok := ident.(interface{ GetTraits() identity.JSON }); ok {
			traits := traitSource.GetTraits()
			// Simple check for demo: if "email" matches
			var m map[string]any
			if err := json.Unmarshal(traits, &m); err == nil {
				traitEmail, ok1 := m["email"].(string)
				filterEmail, ok2 := filter["email"].(string)
				if ok1 && ok2 && traitEmail == filterEmail {
					return ident, nil
				}
			}
		}
	}
	return nil, errors.New("not found")
}

func (s *InMemStorage) ListIdentities(factory func() any, page, limit int) ([]any, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	res := make([]any, 0)
	i := 0
	start := (page - 1) * limit
	for _, ident := range s.identities {
		if i >= start && len(res) < limit {
			res = append(res, ident)
		}
		i++
	}
	return res, nil
}

func (s *InMemStorage) UpdateIdentity(ident any) error {
	return s.CreateIdentity(ident)
}

func (s *InMemStorage) DeleteIdentity(factory func() any, id any) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.identities, fmt.Sprintf("%v", id))
	return nil
}

func (s *InMemStorage) GetCredentialByIdentifier(identifier, method string) (*identity.Credential, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	cred, ok := s.creds[identifier+":"+method]
	if !ok {
		return nil, errors.New("credential not found")
	}
	return cred, nil
}

func (s *InMemStorage) CreateCredential(cred any) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if c, ok := cred.(*identity.Credential); ok {
		s.creds[c.Identifier+":"+c.Type] = c
	}
	return nil
}

func (s *InMemStorage) UpdateCredentialSecret(ctx context.Context, identityID, method, secret string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	
	for _, cred := range s.creds {
		if cred.IdentityID == identityID && cred.Type == method {
			cred.Secret = secret
			return nil
		}
	}
	return errors.New("credential not found")
}

func (s *InMemStorage) SaveEvent(ctx context.Context, event *audit.AuditEvent) error {
	// No-op for demo audit
	return nil
}

func (s *InMemStorage) Query(ctx context.Context, filter audit.Filter) ([]audit.AuditEvent, error) {
	return nil, nil
}

func (s *InMemStorage) Count(ctx context.Context, filter audit.Filter) (int64, error) {
	return 0, nil
}

func (s *InMemStorage) Export(ctx context.Context, filter audit.Filter, format audit.ExportFormat) (io.Reader, error) {
	return nil, nil
}

func (s *InMemStorage) Purge(ctx context.Context, olderThan time.Time) (int64, error) {
	return 0, nil
}

// SessionStorage implementation
func (s *InMemStorage) CreateSession(sess *identity.Session) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sessions[fmt.Sprintf("%v", sess.ID)] = sess
	return nil
}

func (s *InMemStorage) GetSession(id any) (*identity.Session, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	sess, ok := s.sessions[fmt.Sprintf("%v", id)]
	if !ok {
		return nil, errors.New("session not found")
	}
	return sess, nil
}

func (s *InMemStorage) GetSessionByRefreshToken(token string) (*identity.Session, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, sess := range s.sessions {
		if sess.RefreshToken == token {
			return sess, nil
		}
	}
	return nil, errors.New("session not found")
}

func (s *InMemStorage) DeleteSession(id any) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.sessions, fmt.Sprintf("%v", id))
	return nil
}

// TokenStore implementation (for OIDC state/code persistence)
func (s *InMemStorage) SaveToken(ctx context.Context, t *domain.AuthToken) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.tokens[t.Token] = t
	return nil
}

func (s *InMemStorage) GetToken(ctx context.Context, token string) (*domain.AuthToken, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	data, ok := s.tokens[token]
	if !ok {
		return nil, errors.New("token not found")
	}
	
	if t, ok := data.(*domain.AuthToken); ok {
		return t, nil
	}
	return nil, errors.New("unsupported token target type")
}

func (s *InMemStorage) DeleteToken(ctx context.Context, token string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.tokens, token)
	return nil
}

func (s *InMemStorage) DeleteExpiredTokens(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	for k, v := range s.tokens {
		if t, ok := v.(*domain.AuthToken); ok {
			if t.ExpiresAt.Before(now) {
				delete(s.tokens, k)
			}
		}
	}
	return nil
}

// Verify satisfying domain.Storage
var _ domain.Storage = (*InMemStorage)(nil)
