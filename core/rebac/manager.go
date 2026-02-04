package rebac

import (
	"context"
	"fmt"
)

// Manager provides a high-level API for ReBAC operations.
// It wraps the store and checker to provide a convenient interface
// for applications to manage relationships and check permissions.
type Manager struct {
	store   Store
	checker *Checker
	schemas map[string]Schema
}

// ManagerOption configures a Manager.
type ManagerOption func(*Manager)

// NewManager creates a new ReBAC manager.
func NewManager(store Store, opts ...ManagerOption) *Manager {
	m := &Manager{
		store:   store,
		schemas: make(map[string]Schema),
	}

	for _, opt := range opts {
		opt(m)
	}

	// Create checker with schemas
	schemas := make([]Schema, 0, len(m.schemas))
	for _, s := range m.schemas {
		schemas = append(schemas, s)
	}
	m.checker = NewChecker(store, WithSchemas(schemas))

	return m
}

// WithSchema adds schema configuration for computed relations.
func WithSchema(schema Schema) ManagerOption {
	return func(m *Manager) {
		m.schemas[schema.Type] = schema
	}
}

// Grant creates a relationship tuple.
// Example: Grant("user", "alice", "viewer", "document", "123")
// Creates: user:alice#viewer@document:123
func (m *Manager) Grant(ctx context.Context, subjectType, subjectID, relation, objectType, objectID string) error {
	tuple := NewTuple(subjectType, subjectID, relation, objectType, objectID)
	return m.store.WriteTuple(ctx, tuple)
}

// GrantUserset creates a relationship tuple with a userset subject.
// Example: GrantUserset("group", "engineering", "member", "viewer", "document", "123")
// Creates: group:engineering#member#viewer@document:123
// This means "all members of engineering group are viewers of document 123"
func (m *Manager) GrantUserset(ctx context.Context, subjectType, subjectID, subjectRelation, relation, objectType, objectID string) error {
	tuple := NewUsersetTuple(subjectType, subjectID, subjectRelation, relation, objectType, objectID)
	return m.store.WriteTuple(ctx, tuple)
}

// Revoke removes a relationship tuple.
func (m *Manager) Revoke(ctx context.Context, subjectType, subjectID, relation, objectType, objectID string) error {
	tuple := NewTuple(subjectType, subjectID, relation, objectType, objectID)
	return m.store.DeleteTuple(ctx, tuple)
}

// RevokeUserset removes a userset relationship tuple.
func (m *Manager) RevokeUserset(ctx context.Context, subjectType, subjectID, subjectRelation, relation, objectType, objectID string) error {
	tuple := NewUsersetTuple(subjectType, subjectID, subjectRelation, relation, objectType, objectID)
	return m.store.DeleteTuple(ctx, tuple)
}

// Check verifies if a subject has a specific relation to an object.
// This checks direct assignments as well as computed relations and group memberships.
func (m *Manager) Check(ctx context.Context, subjectType, subjectID, relation, objectType, objectID string) (bool, error) {
	subject := NewSubjectRef(subjectType, subjectID)
	object := NewObjectRef(objectType, objectID)
	return m.checker.Check(ctx, subject, relation, object)
}

// ListObjects returns all objects of a type where the subject has the given relation.
// This performs a reverse lookup to find all accessible resources.
func (m *Manager) ListObjects(ctx context.Context, subjectType, subjectID, relation, objectType string) ([]ObjectRef, error) {
	// Get all tuples where the subject has this relation with objects of the type
	tuples, err := m.store.ReadTuples(ctx, TupleFilter{
		SubjectType: subjectType,
		SubjectID:   subjectID,
		Relation:    relation,
		ObjectType:  objectType,
	})
	if err != nil {
		return nil, err
	}

	result := make([]ObjectRef, 0, len(tuples))
	seen := make(map[string]bool)

	for _, t := range tuples {
		key := t.Object.String()
		if !seen[key] {
			result = append(result, t.Object)
			seen[key] = true
		}
	}

	return result, nil
}

// ListSubjects returns all subjects that have the given relation to an object.
func (m *Manager) ListSubjects(ctx context.Context, relation, objectType, objectID string) ([]SubjectRef, error) {
	tuples, err := m.store.ReadTuples(ctx, TupleFilter{
		Relation:   relation,
		ObjectType: objectType,
		ObjectID:   objectID,
	})
	if err != nil {
		return nil, err
	}

	result := make([]SubjectRef, 0, len(tuples))
	for _, t := range tuples {
		result = append(result, t.Subject)
	}

	return result, nil
}

// AddToGroup adds a user as a member of a group.
// Shorthand for Grant("user", userID, "member", "group", groupID)
func (m *Manager) AddToGroup(ctx context.Context, userID, groupID string) error {
	return m.Grant(ctx, "user", userID, "member", "group", groupID)
}

// RemoveFromGroup removes a user from a group.
func (m *Manager) RemoveFromGroup(ctx context.Context, userID, groupID string) error {
	return m.Revoke(ctx, "user", userID, "member", "group", groupID)
}

// SetParent establishes a parent-child relationship between resources.
// The parent is stored as the subject of a "parent" relation on the child.
// Example: SetParent("folder", "home", "document", "123")
// Creates: folder:home#parent@document:123 (Document 123's parent is folder home)
func (m *Manager) SetParent(ctx context.Context, parentType, parentID, childType, childID string) error {
	tuple := Tuple{
		Subject:  NewSubjectRef(parentType, parentID),
		Relation: "parent",
		Object:   NewObjectRef(childType, childID),
	}
	return m.store.WriteTuple(ctx, tuple)
}

// GetParent returns the parent of a resource, if any.
func (m *Manager) GetParent(ctx context.Context, childType, childID string) (*ObjectRef, error) {
	tuples, err := m.store.ReadTuples(ctx, TupleFilter{
		Relation:   "parent",
		ObjectType: childType,
		ObjectID:   childID,
	})
	if err != nil {
		return nil, err
	}

	if len(tuples) == 0 {
		return nil, nil
	}

	// Return the first parent (resources typically have one parent)
	return &tuples[0].Subject.Object, nil
}

// RequirePermission returns an error if the subject does not have the relation.
func (m *Manager) RequirePermission(ctx context.Context, subjectType, subjectID, relation, objectType, objectID string) error {
	allowed, err := m.Check(ctx, subjectType, subjectID, relation, objectType, objectID)
	if err != nil {
		return err
	}
	if !allowed {
		return fmt.Errorf("rebac: permission denied: %s:%s does not have %s on %s:%s",
			subjectType, subjectID, relation, objectType, objectID)
	}
	return nil
}

// ============================================================================
// policy.Engine Implementation
// ============================================================================
//
// The Manager implements policy.Engine interface to integrate with the
// unified authorization system. This allows using ReBAC in HybridStrategy
// and applying middleware like AuditMiddleware and CachingMiddleware.
//
// Usage with policy.Engine:
//
//	manager := rebac.NewManager(store)
//	// manager implements policy.Engine
//	allowed, _ := manager.Can(ctx, subject, "viewer", resource)

// SubjectExtractor converts any subject to ReBAC subject type and ID.
type SubjectExtractor func(subject any) (subjectType, subjectID string, err error)

// ObjectExtractor converts any resource to ReBAC object type and ID.
type ObjectExtractor func(resource any) (objectType, objectID string, err error)

// SubjectInfo provides explicit subject type and ID for Can() checks.
type SubjectInfo struct {
	Type string
	ID   string
}

// ResourceInfo provides explicit resource type and ID for Can() checks.
type ResourceInfo struct {
	Type string
	ID   string
}

// extractors hold the configured extractors for Can() method.
// By default, Manager uses DefaultSubjectExtractor and DefaultObjectExtractor.
var (
	defaultSubjectExtractor SubjectExtractor = DefaultSubjectExtractor
	defaultObjectExtractor  ObjectExtractor  = DefaultObjectExtractor
)

// DefaultSubjectExtractor handles common subject types.
// Supports: SubjectInfo, string (treated as user ID)
func DefaultSubjectExtractor(subject any) (subjectType, subjectID string, err error) {
	switch v := subject.(type) {
	case SubjectInfo:
		return v.Type, v.ID, nil
	case string:
		return "user", v, nil
	default:
		return "", "", fmt.Errorf("rebac: unsupported subject type: %T (use SubjectInfo or string)", subject)
	}
}

// DefaultObjectExtractor handles common resource types.
// Supports: ResourceInfo, string (treated as resource ID)
func DefaultObjectExtractor(resource any) (objectType, objectID string, err error) {
	switch v := resource.(type) {
	case ResourceInfo:
		return v.Type, v.ID, nil
	case string:
		return "resource", v, nil
	default:
		return "", "", fmt.Errorf("rebac: unsupported resource type: %T (use ResourceInfo or string)", resource)
	}
}

// Can implements policy.Engine interface.
// It allows using the Manager directly in the policy framework.
//
// The subject and resource are converted using extractors:
//   - SubjectInfo{Type: "user", ID: "alice"} → user:alice
//   - "alice" (string) → user:alice (default type)
//   - ResourceInfo{Type: "document", ID: "123"} → document:123
//
// Example:
//
//	manager.Can(ctx, rebac.SubjectInfo{Type: "user", ID: "alice"}, "viewer", rebac.ResourceInfo{Type: "document", ID: "123"})
func (m *Manager) Can(ctx context.Context, subject any, action string, resource any) (bool, error) {
	subType, subID, err := defaultSubjectExtractor(subject)
	if err != nil {
		return false, err
	}

	objType, objID, err := defaultObjectExtractor(resource)
	if err != nil {
		return false, err
	}

	return m.Check(ctx, subType, subID, action, objType, objID)
}
