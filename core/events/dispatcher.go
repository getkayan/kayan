package events

import (
	"context"
	"sync"
)

// DefaultDispatcher implements a thread-safe, in-memory event dispatcher.
type DefaultDispatcher struct {
	mu          sync.RWMutex
	subscribers map[Topic][]Handler
}

// NewDispatcher creates a new DefaultDispatcher.
func NewDispatcher() *DefaultDispatcher {
	return &DefaultDispatcher{
		subscribers: make(map[Topic][]Handler),
	}
}

// Subscribe registers a handler for a topic.
func (d *DefaultDispatcher) Subscribe(topic Topic, handler Handler) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.subscribers[topic] = append(d.subscribers[topic], handler)
}

// Dispatch broadcasts an event to all matching subscribers.
func (d *DefaultDispatcher) Dispatch(ctx context.Context, event Event) error {
	d.mu.RLock()
	handlers := d.subscribers[event.Topic]
	globals := d.subscribers[Topic("*")]
	d.mu.RUnlock()

	// Execute handlers
	// For now, we execute them synchronously to ensure consistency,
	// but a real implementation might use a worker pool or goroutines.
	for _, h := range handlers {
		if err := h(ctx, event); err != nil {
			// In a library, we might want to log or continue? 
			// Let's continue to other handlers but track the error.
			continue 
		}
	}

	for _, h := range globals {
		if err := h(ctx, event); err != nil {
			continue
		}
	}

	return nil
}
