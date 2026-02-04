package rebac

import (
	"context"
)

// Store defines the interface for persisting and querying relation tuples.
// Implementations can use in-memory storage, SQL databases, or specialized
// graph databases depending on scale requirements.
type Store interface {
	// WriteTuple creates or updates a relationship tuple.
	// If the tuple already exists, this is a no-op.
	WriteTuple(ctx context.Context, tuple Tuple) error

	// WriteTuples creates multiple tuples atomically.
	WriteTuples(ctx context.Context, tuples []Tuple) error

	// DeleteTuple removes a specific relationship tuple.
	DeleteTuple(ctx context.Context, tuple Tuple) error

	// DeleteTuples removes all tuples matching the filter.
	DeleteTuples(ctx context.Context, filter TupleFilter) error

	// ReadTuples returns all tuples matching the filter.
	ReadTuples(ctx context.Context, filter TupleFilter) ([]Tuple, error)

	// TupleExists checks if a specific tuple exists.
	TupleExists(ctx context.Context, tuple Tuple) (bool, error)
}

// StoreOption configures a Store implementation.
type StoreOption func(any)
