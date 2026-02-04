package rebac

import (
	"context"
	"sync"
)

// MemoryStore provides an in-memory implementation of Store.
// This is useful for testing, development, and simple single-instance deployments.
// For production use with high availability requirements, use a persistent store.
type MemoryStore struct {
	mu     sync.RWMutex
	tuples []Tuple
}

// NewMemoryStore creates a new in-memory tuple store.
func NewMemoryStore() *MemoryStore {
	return &MemoryStore{
		tuples: make([]Tuple, 0),
	}
}

// WriteTuple adds a tuple to the store if it doesn't already exist.
func (s *MemoryStore) WriteTuple(ctx context.Context, tuple Tuple) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Check for duplicate
	for _, t := range s.tuples {
		if tuplesEqual(t, tuple) {
			return nil // Already exists, no-op
		}
	}

	s.tuples = append(s.tuples, tuple)
	return nil
}

// WriteTuples adds multiple tuples atomically.
func (s *MemoryStore) WriteTuples(ctx context.Context, tuples []Tuple) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	for _, tuple := range tuples {
		exists := false
		for _, t := range s.tuples {
			if tuplesEqual(t, tuple) {
				exists = true
				break
			}
		}
		if !exists {
			s.tuples = append(s.tuples, tuple)
		}
	}

	return nil
}

// DeleteTuple removes a specific tuple from the store.
func (s *MemoryStore) DeleteTuple(ctx context.Context, tuple Tuple) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	for i, t := range s.tuples {
		if tuplesEqual(t, tuple) {
			// Remove by swapping with last element and truncating
			s.tuples[i] = s.tuples[len(s.tuples)-1]
			s.tuples = s.tuples[:len(s.tuples)-1]
			return nil
		}
	}

	return nil // Not found is not an error
}

// DeleteTuples removes all tuples matching the filter.
func (s *MemoryStore) DeleteTuples(ctx context.Context, filter TupleFilter) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Build new slice without matching tuples
	newTuples := make([]Tuple, 0, len(s.tuples))
	for _, t := range s.tuples {
		if !filter.Matches(t) {
			newTuples = append(newTuples, t)
		}
	}
	s.tuples = newTuples

	return nil
}

// ReadTuples returns all tuples matching the filter.
func (s *MemoryStore) ReadTuples(ctx context.Context, filter TupleFilter) ([]Tuple, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var result []Tuple
	for _, t := range s.tuples {
		if filter.Matches(t) {
			result = append(result, t)
		}
	}

	return result, nil
}

// TupleExists checks if a specific tuple exists.
func (s *MemoryStore) TupleExists(ctx context.Context, tuple Tuple) (bool, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	for _, t := range s.tuples {
		if tuplesEqual(t, tuple) {
			return true, nil
		}
	}

	return false, nil
}

// tuplesEqual checks if two tuples are identical.
func tuplesEqual(a, b Tuple) bool {
	return a.Subject.Object.Type == b.Subject.Object.Type &&
		a.Subject.Object.ID == b.Subject.Object.ID &&
		a.Subject.Relation == b.Subject.Relation &&
		a.Relation == b.Relation &&
		a.Object.Type == b.Object.Type &&
		a.Object.ID == b.Object.ID
}

// Compile-time interface check
var _ Store = (*MemoryStore)(nil)
