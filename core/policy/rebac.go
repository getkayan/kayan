package policy

import (
	"context"
	"fmt"
)

// RelationChecker defines an interface for checking relationships between entities.
// This decouples the ReBAC strategy from the underlying graph store (e.g. SpiceDB, SQL, Neo4j).
type RelationChecker interface {
	// CheckRelation returns true if 'subject' has 'relation' to 'object'.
	CheckRelation(ctx context.Context, subject any, relation string, object any) (bool, error)
}

// ReBACStrategy implements Relationship-Based Access Control.
// It delegates relationship checks to a RelationChecker.
// The 'action' in Can() is interpreted as the 'relation' to check.
// e.g. Can(user, "viewer", doc) -> checks relation "viewer" between user and doc.
type ReBACStrategy struct {
	checker RelationChecker
}

func NewReBACStrategy(checker RelationChecker) *ReBACStrategy {
	return &ReBACStrategy{checker: checker}
}

func (s *ReBACStrategy) Can(ctx context.Context, subject any, action string, resource any) (bool, error) {
	if s.checker == nil {
		return false, fmt.Errorf("rebac: checker not configured")
	}
	return s.checker.CheckRelation(ctx, subject, action, resource)
}
