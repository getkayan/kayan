// Package kayantesting provides in-memory implementations of Kayan's storage
// contracts, plus a contract test suite any implementation can run.
//
// Not for production use. Everything here keeps state in process memory and is
// lost on restart. It exists so tests and examples do not each hand-roll a
// store, and so a new backend can prove it satisfies the same contract the
// bundled adapters do.
//
// # Testing your own storage backend
//
// [StorageSuite] exercises the whole of [domain.Storage]. Point it at a
// constructor and it reports where your implementation diverges:
//
//	func TestMongoStore(t *testing.T) {
//	    kayantesting.StorageSuite(t, func() domain.Storage {
//	        return mongostore.New(testDatabase(t))
//	    })
//	}
//
// # Deterministic time
//
// [FakeClock] satisfies [domain.Clock], so expiry can be driven to an exact
// instant instead of sleeping:
//
//	clock := kayantesting.NewFakeClock(time.Now())
//	clock.Advance(2 * time.Hour)
package kayantesting

import (
	"context"
	"errors"
	"fmt"
	"io"
	"reflect"
	"slices"
	"sync"
	"time"

	"github.com/getkayan/kayan/core/audit"
	"github.com/getkayan/kayan/core/domain"
	"github.com/getkayan/kayan/core/identity"
)

// Errors reported by [MemoryStore]. They match the wording storage adapters
// conventionally use, so tests asserting on them behave the same either way.
var (
	ErrNotFound      = errors.New("kayantesting: not found")
	ErrAlreadyExists = errors.New("kayantesting: already exists")
)

// MemoryStore is an in-memory [domain.Storage].
//
// Not for production use: all state is per-process and lost on restart.
//
// It is safe for concurrent use. Stored values are the caller's pointers, not
// copies, matching how the GORM adapter behaves after a write.
type MemoryStore struct {
	mu sync.RWMutex

	identities  map[string]any
	credentials map[string]*identity.Credential // keyed by method + "\x00" + identifier
	sessions    map[string]*identity.Session
	byRefresh   map[string]*identity.Session
	tokens      map[string]*domain.AuthToken
	events      []*audit.AuditEvent

	clock domain.Clock
}

// Compile-time proof that the in-memory store satisfies the full contract.
var _ domain.Storage = (*MemoryStore)(nil)

// MemoryStoreOption configures a [MemoryStore].
type MemoryStoreOption func(*MemoryStore)

// WithClock sets the clock used for timestamps. Defaults to
// [domain.SystemClock].
func WithClock(c domain.Clock) MemoryStoreOption {
	return func(s *MemoryStore) { s.clock = c }
}

// NewMemoryStore returns an empty in-memory store.
//
// Not for production use.
func NewMemoryStore(opts ...MemoryStoreOption) *MemoryStore {
	s := &MemoryStore{
		identities:  make(map[string]any),
		credentials: make(map[string]*identity.Credential),
		sessions:    make(map[string]*identity.Session),
		byRefresh:   make(map[string]*identity.Session),
		tokens:      make(map[string]*domain.AuthToken),
		clock:       domain.SystemClock,
	}
	for _, opt := range opts {
		opt(s)
	}
	s.clock = domain.ClockOrDefault(s.clock)
	return s
}

// Reset empties the store, so one instance can serve several subtests.
func (s *MemoryStore) Reset() {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.identities = make(map[string]any)
	s.credentials = make(map[string]*identity.Credential)
	s.sessions = make(map[string]*identity.Session)
	s.byRefresh = make(map[string]*identity.Session)
	s.tokens = make(map[string]*domain.AuthToken)
	s.events = nil
}

// --- IdentityStorage ---

// CreateIdentity stores ident, which must expose a non-empty ID.
func (s *MemoryStore) CreateIdentity(ctx context.Context, ident any) error {
	id, err := identityID(ident)
	if err != nil {
		return err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.identities[id]; exists {
		return fmt.Errorf("%w: identity %q", ErrAlreadyExists, id)
	}
	s.identities[id] = ident
	return nil
}

// GetIdentity returns the identity with the given ID.
//
// The factory is accepted for parity with the storage contract; the stored
// value is returned as-is, since an in-memory store has nothing to decode.
func (s *MemoryStore) GetIdentity(ctx context.Context, _ func() any, id any) (any, error) {
	key := fmt.Sprintf("%v", id)

	s.mu.RLock()
	defer s.mu.RUnlock()

	if ident, ok := s.identities[key]; ok {
		return ident, nil
	}
	return nil, fmt.Errorf("%w: identity %q", ErrNotFound, key)
}

// FindIdentity returns the first identity whose fields all match query.
//
// Keys are Go struct field names, matched by reflection, exactly as the GORM
// adapter and the flow strategies expect.
func (s *MemoryStore) FindIdentity(ctx context.Context, _ func() any, query map[string]any) (any, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	for _, ident := range s.identities {
		if matchesQuery(ident, query) {
			return ident, nil
		}
	}
	return nil, fmt.Errorf("%w: no identity matches %v", ErrNotFound, query)
}

// ListIdentities returns one page of identities. Pages are 1-based; a limit of
// zero or less returns every identity.
//
// Order is not specified, matching a store with no explicit sort.
func (s *MemoryStore) ListIdentities(ctx context.Context, _ func() any, page, limit int) ([]any, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	all := make([]any, 0, len(s.identities))
	for _, ident := range s.identities {
		all = append(all, ident)
	}

	if limit <= 0 {
		return all, nil
	}
	if page < 1 {
		page = 1
	}

	start := (page - 1) * limit
	if start >= len(all) {
		return []any{}, nil
	}
	end := min(start+limit, len(all))
	return all[start:end], nil
}

// UpdateIdentity replaces the stored identity with the same ID.
func (s *MemoryStore) UpdateIdentity(ctx context.Context, ident any) error {
	id, err := identityID(ident)
	if err != nil {
		return err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.identities[id]; !exists {
		return fmt.Errorf("%w: identity %q", ErrNotFound, id)
	}
	s.identities[id] = ident
	return nil
}

// DeleteIdentity removes the identity with the given ID.
func (s *MemoryStore) DeleteIdentity(ctx context.Context, _ func() any, id any) error {
	key := fmt.Sprintf("%v", id)

	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.identities[key]; !exists {
		return fmt.Errorf("%w: identity %q", ErrNotFound, key)
	}
	delete(s.identities, key)
	return nil
}

// --- CredentialStorage ---

// CreateCredential stores cred, which must be an *identity.Credential.
func (s *MemoryStore) CreateCredential(ctx context.Context, cred any) error {
	c, ok := cred.(*identity.Credential)
	if !ok {
		return fmt.Errorf("kayantesting: credential is %T, want *identity.Credential", cred)
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	// The storage contract calls this dimension "method"; the stored field is
	// Credential.Type.
	s.credentials[credentialKey(c.Identifier, c.Type)] = c
	return nil
}

// GetCredentialByIdentifier returns the credential for an identifier and method.
func (s *MemoryStore) GetCredentialByIdentifier(ctx context.Context, identifier, method string) (*identity.Credential, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if c, ok := s.credentials[credentialKey(identifier, method)]; ok {
		return c, nil
	}
	return nil, fmt.Errorf("%w: credential %q/%q", ErrNotFound, method, identifier)
}

// UpdateCredentialSecret replaces the secret on every credential belonging to
// an identity for the given method.
func (s *MemoryStore) UpdateCredentialSecret(_ context.Context, identityID, method, secret string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	updated := false
	for _, c := range s.credentials {
		if c.IdentityID == identityID && c.Type == method {
			c.Secret = secret
			updated = true
		}
	}
	if !updated {
		return fmt.Errorf("%w: credential for identity %q method %q", ErrNotFound, identityID, method)
	}
	return nil
}

// --- SessionStorage ---

// CreateSession stores a session and indexes it by refresh token.
func (s *MemoryStore) CreateSession(ctx context.Context, sess *identity.Session) error {
	if sess == nil {
		return errors.New("kayantesting: nil session")
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	s.sessions[sess.ID] = sess
	if sess.RefreshToken != "" {
		s.byRefresh[sess.RefreshToken] = sess
	}
	return nil
}

// GetSession returns the session with the given ID.
func (s *MemoryStore) GetSession(ctx context.Context, id any) (*identity.Session, error) {
	key := fmt.Sprintf("%v", id)

	s.mu.RLock()
	defer s.mu.RUnlock()

	if sess, ok := s.sessions[key]; ok {
		return sess, nil
	}
	return nil, fmt.Errorf("%w: session %q", ErrNotFound, key)
}

// GetSessionByRefreshToken returns the session holding the given refresh token.
func (s *MemoryStore) GetSessionByRefreshToken(ctx context.Context, token string) (*identity.Session, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if sess, ok := s.byRefresh[token]; ok {
		return sess, nil
	}
	return nil, fmt.Errorf("%w: session for refresh token", ErrNotFound)
}

// DeleteSession removes a session and its refresh-token index entry.
func (s *MemoryStore) DeleteSession(ctx context.Context, id any) error {
	key := fmt.Sprintf("%v", id)

	s.mu.Lock()
	defer s.mu.Unlock()

	sess, ok := s.sessions[key]
	if !ok {
		return fmt.Errorf("%w: session %q", ErrNotFound, key)
	}
	delete(s.sessions, key)
	if sess.RefreshToken != "" {
		delete(s.byRefresh, sess.RefreshToken)
	}
	return nil
}

// --- TokenStore ---

// SaveToken stores a transient authentication token.
func (s *MemoryStore) SaveToken(_ context.Context, token *domain.AuthToken) error {
	if token == nil {
		return errors.New("kayantesting: nil token")
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	s.tokens[token.Token] = token
	return nil
}

// GetToken returns a token by value. Expired tokens are reported as not found,
// matching a store that filters on expiry.
func (s *MemoryStore) GetToken(_ context.Context, token string) (*domain.AuthToken, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	t, ok := s.tokens[token]
	if !ok {
		return nil, fmt.Errorf("%w: token", ErrNotFound)
	}
	if !t.ExpiresAt.IsZero() && !s.clock.Now().Before(t.ExpiresAt) {
		return nil, fmt.Errorf("%w: token expired", ErrNotFound)
	}
	return t, nil
}

// DeleteToken removes a token.
func (s *MemoryStore) DeleteToken(_ context.Context, token string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	delete(s.tokens, token)
	return nil
}

// DeleteExpiredTokens removes every token whose expiry has passed.
func (s *MemoryStore) DeleteExpiredTokens(context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := s.clock.Now()
	for value, t := range s.tokens {
		if !t.ExpiresAt.IsZero() && !now.Before(t.ExpiresAt) {
			delete(s.tokens, value)
		}
	}
	return nil
}

// --- AuditStore ---

// SaveEvent appends an audit event.
func (s *MemoryStore) SaveEvent(_ context.Context, event *audit.AuditEvent) error {
	if event == nil {
		return errors.New("kayantesting: nil audit event")
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	s.events = append(s.events, event)
	return nil
}

// Query returns audit events matching filter.
func (s *MemoryStore) Query(_ context.Context, filter audit.Filter) ([]audit.AuditEvent, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	out := make([]audit.AuditEvent, 0)
	for _, e := range s.events {
		if matchesAuditFilter(e, filter) {
			out = append(out, *e)
		}
	}

	// Honor pagination. A store that silently ignores Limit hands back the
	// whole table to a caller that asked for a page.
	if filter.Offset > 0 {
		if filter.Offset >= len(out) {
			return []audit.AuditEvent{}, nil
		}
		out = out[filter.Offset:]
	}
	if filter.Limit > 0 && filter.Limit < len(out) {
		out = out[:filter.Limit]
	}
	return out, nil
}

// Count returns the number of audit events matching filter.
//
// Pagination is ignored: Count reports how many events match, which is what a
// caller needs to compute the number of pages.
func (s *MemoryStore) Count(_ context.Context, filter audit.Filter) (int64, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var n int64
	for _, e := range s.events {
		if matchesAuditFilter(e, filter) {
			n++
		}
	}
	return n, nil
}

// Export is not implemented; [MemoryStore] is a test double, and export
// formatting belongs to real adapters.
func (s *MemoryStore) Export(context.Context, audit.Filter, audit.ExportFormat) (io.Reader, error) {
	return nil, errors.New("kayantesting: Export is not implemented")
}

// Purge deletes audit events recorded before olderThan and returns the count.
func (s *MemoryStore) Purge(_ context.Context, olderThan time.Time) (int64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	kept := s.events[:0]
	var purged int64
	for _, e := range s.events {
		if e.CreatedAt.Before(olderThan) {
			purged++
			continue
		}
		kept = append(kept, e)
	}
	s.events = kept
	return purged, nil
}

// Events returns a copy of every recorded audit event, for assertions.
func (s *MemoryStore) Events() []audit.AuditEvent {
	s.mu.RLock()
	defer s.mu.RUnlock()

	out := make([]audit.AuditEvent, 0, len(s.events))
	for _, e := range s.events {
		out = append(out, *e)
	}
	return out
}

// --- helpers ---

// identityID extracts an ID from an identity, accepting either a GetID method
// or an ID field.
func identityID(ident any) (string, error) {
	if ident == nil {
		return "", errors.New("kayantesting: nil identity")
	}

	if g, ok := ident.(interface{ GetID() any }); ok {
		if id := g.GetID(); id != nil {
			if s := fmt.Sprintf("%v", id); s != "" {
				return s, nil
			}
		}
		return "", errors.New("kayantesting: identity has an empty ID")
	}

	v := reflect.ValueOf(ident)
	for v.Kind() == reflect.Ptr {
		if v.IsNil() {
			return "", errors.New("kayantesting: nil identity")
		}
		v = v.Elem()
	}
	if v.Kind() != reflect.Struct {
		return "", fmt.Errorf("kayantesting: identity is %T, want a struct", ident)
	}

	f := v.FieldByName("ID")
	if !f.IsValid() {
		return "", fmt.Errorf("kayantesting: %T has neither GetID() nor an ID field", ident)
	}
	id := fmt.Sprintf("%v", f.Interface())
	if id == "" {
		return "", errors.New("kayantesting: identity has an empty ID")
	}
	return id, nil
}

// matchesQuery reports whether every field in query matches ident. Comparison
// is by formatted value, mirroring the reflection matching used elsewhere.
func matchesQuery(ident any, query map[string]any) bool {
	v := reflect.ValueOf(ident)
	for v.Kind() == reflect.Ptr {
		if v.IsNil() {
			return false
		}
		v = v.Elem()
	}
	if v.Kind() != reflect.Struct {
		return false
	}

	for field, want := range query {
		f := v.FieldByName(field)
		if !f.IsValid() {
			return false
		}
		if fmt.Sprintf("%v", f.Interface()) != fmt.Sprintf("%v", want) {
			return false
		}
	}
	return true
}

// credentialKey builds the composite key for a credential. The method is first
// so the separator cannot be forged by an identifier containing one.
func credentialKey(identifier, method string) string {
	return method + "\x00" + identifier
}

func matchesAuditFilter(e *audit.AuditEvent, f audit.Filter) bool {
	switch {
	case f.TenantID != "" && e.TenantID != f.TenantID:
		return false
	case f.ActorID != "" && e.ActorID != f.ActorID:
		return false
	case f.SubjectID != "" && e.SubjectID != f.SubjectID:
		return false
	case f.ResourceType != "" && e.ResourceType != f.ResourceType:
		return false
	case f.ResourceID != "" && e.ResourceID != f.ResourceID:
		return false
	case f.IPAddress != "" && e.IPAddress != f.IPAddress:
		return false
	case f.SessionID != "" && e.SessionID != f.SessionID:
		return false
	case len(f.Types) > 0 && !slices.Contains(f.Types, e.Type):
		return false
	case len(f.Statuses) > 0 && !slices.Contains(f.Statuses, e.Status):
		return false
	case len(f.RiskLevels) > 0 && !slices.Contains(f.RiskLevels, e.Risk):
		return false
	case !f.StartTime.IsZero() && e.CreatedAt.Before(f.StartTime):
		return false
	case !f.EndTime.IsZero() && e.CreatedAt.After(f.EndTime):
		return false
	}
	return true
}
