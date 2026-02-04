package rebac

import (
	"context"
	"fmt"
)

// DefaultMaxDepth is the default maximum recursion depth for permission checks.
const DefaultMaxDepth = 25

// Checker performs permission checks by traversing the relation graph.
// It supports:
//   - Direct tuple lookups
//   - Userset expansion (group membership)
//   - Computed relations (role inheritance)
//   - Tuple-to-userset (hierarchical permissions)
type Checker struct {
	store    Store
	schemas  map[string]Schema
	maxDepth int
}

// CheckerOption configures a Checker.
type CheckerOption func(*Checker)

// WithMaxDepth sets the maximum recursion depth for permission checks.
func WithMaxDepth(depth int) CheckerOption {
	return func(c *Checker) {
		c.maxDepth = depth
	}
}

// WithSchemas sets the authorization schemas.
func WithSchemas(schemas []Schema) CheckerOption {
	return func(c *Checker) {
		for _, s := range schemas {
			c.schemas[s.Type] = s
		}
	}
}

// NewChecker creates a new permission checker.
func NewChecker(store Store, opts ...CheckerOption) *Checker {
	c := &Checker{
		store:    store,
		schemas:  make(map[string]Schema),
		maxDepth: DefaultMaxDepth,
	}

	for _, opt := range opts {
		opt(c)
	}

	return c
}

// Check returns true if the subject has the specified relation to the object.
// This is the main entry point for permission checking.
func (c *Checker) Check(ctx context.Context, subject SubjectRef, relation string, object ObjectRef) (bool, error) {
	return c.checkWithDepth(ctx, subject, relation, object, 0, make(map[string]bool))
}

// checkWithDepth performs the recursive permission check with cycle detection.
func (c *Checker) checkWithDepth(ctx context.Context, subject SubjectRef, relation string, object ObjectRef, depth int, visited map[string]bool) (bool, error) {
	// Prevent infinite recursion
	if depth > c.maxDepth {
		return false, fmt.Errorf("rebac: max recursion depth exceeded")
	}

	// Cycle detection
	key := fmt.Sprintf("%s#%s@%s", subject.String(), relation, object.String())
	if visited[key] {
		return false, nil
	}
	visited[key] = true

	// Step 1: Check for direct tuple match
	directFound, err := c.checkDirectTuple(ctx, subject, relation, object)
	if err != nil {
		return false, err
	}
	if directFound {
		return true, nil
	}

	// Step 2: If subject is direct (not userset), check if subject is in any userset that has access
	if !subject.IsUserset() {
		found, err := c.checkViaUsersets(ctx, subject, relation, object, depth, visited)
		if err != nil {
			return false, err
		}
		if found {
			return true, nil
		}
	}

	// Step 3: Check computed relations (from schema)
	schema, hasSchema := c.schemas[object.Type]
	if hasSchema {
		if relConfig, ok := schema.Relations[relation]; ok {
			for _, computed := range relConfig.ComputedFrom {
				// Check direct relation inheritance (e.g., owner → editor → viewer)
				if computed.Relation != "" {
					found, err := c.checkWithDepth(ctx, subject, computed.Relation, object, depth+1, visited)
					if err != nil {
						return false, err
					}
					if found {
						return true, nil
					}
				}

				// Check tuple-to-userset (e.g., parent folder's viewers)
				if computed.TupleToUserset != nil {
					found, err := c.checkTupleToUserset(ctx, subject, relation, object, computed.TupleToUserset, depth, visited)
					if err != nil {
						return false, err
					}
					if found {
						return true, nil
					}
				}
			}
		}
	}

	return false, nil
}

// checkDirectTuple checks if a tuple (subject, relation, object) exists directly.
func (c *Checker) checkDirectTuple(ctx context.Context, subject SubjectRef, relation string, object ObjectRef) (bool, error) {
	tuple := Tuple{
		Subject:  subject,
		Relation: relation,
		Object:   object,
	}
	return c.store.TupleExists(ctx, tuple)
}

// checkViaUsersets checks if the subject is a member of any userset that has the relation.
// For example, if "group:eng#member@document:123#viewer" exists, and "group:eng#member@user:alice" exists,
// then Alice (via group membership) is a viewer.
func (c *Checker) checkViaUsersets(ctx context.Context, subject SubjectRef, relation string, object ObjectRef, depth int, visited map[string]bool) (bool, error) {
	// Find all tuples where the object has this relation via a userset
	tuples, err := c.store.ReadTuples(ctx, TupleFilter{
		Relation:   relation,
		ObjectType: object.Type,
		ObjectID:   object.ID,
	})
	if err != nil {
		return false, err
	}

	for _, t := range tuples {
		// Skip direct subject matches (already checked)
		if !t.Subject.IsUserset() {
			continue
		}

		// Check if our subject is a member of this userset
		// For example: t.Subject = group:eng#member
		// Check if subject is a "member" of "group:eng"
		memberFound, err := c.checkWithDepth(ctx, subject, t.Subject.Relation, t.Subject.Object, depth+1, visited)
		if err != nil {
			return false, err
		}
		if memberFound {
			return true, nil
		}
	}

	return false, nil
}

// checkTupleToUserset follows a relation to another object and checks permissions there.
// For example, to check document:123#viewer via parent:
//  1. Find tuples (*, "parent", document:123) → get folder:456
//  2. Check if subject is folder:456#viewer
func (c *Checker) checkTupleToUserset(ctx context.Context, subject SubjectRef, relation string, object ObjectRef, ttu *TupleToUserset, depth int, visited map[string]bool) (bool, error) {
	// Find all objects that our object has the tupleset relation to
	tuples, err := c.store.ReadTuples(ctx, TupleFilter{
		Relation:   ttu.TuplesetRelation,
		ObjectType: object.Type,
		ObjectID:   object.ID,
	})
	if err != nil {
		return false, err
	}

	for _, t := range tuples {
		// The subject of this tuple is the "parent" or related object
		relatedObject := t.Subject.Object

		// Check if our subject has the computed relation on this related object
		found, err := c.checkWithDepth(ctx, subject, ttu.ComputedRelation, relatedObject, depth+1, visited)
		if err != nil {
			return false, err
		}
		if found {
			return true, nil
		}
	}

	return false, nil
}
