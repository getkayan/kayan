package events

import (
	"context"
	"sync"
)

// DispatcherOption configures a DefaultDispatcher.
type DispatcherOption func(*DefaultDispatcher)

// WithAsync enables asynchronous event dispatch. Handlers run in separate goroutines
// and Dispatch returns immediately.
func WithAsync() DispatcherOption {
	return func(d *DefaultDispatcher) { d.async = true }
}

// WithErrorHandler sets a callback for handler errors during async dispatch.
func WithErrorHandler(h func(error)) DispatcherOption {
	return func(d *DefaultDispatcher) { d.errHandler = h }
}

// DefaultDispatcher implements a thread-safe, in-memory event dispatcher.
type DefaultDispatcher struct {
	mu          sync.RWMutex
	subscribers map[Topic][]Handler
	async       bool
	errHandler  func(error)
}

// NewDispatcher creates a new DefaultDispatcher.
func NewDispatcher(opts ...DispatcherOption) *DefaultDispatcher {
	d := &DefaultDispatcher{
		subscribers: make(map[Topic][]Handler),
	}
	for _, opt := range opts {
		opt(d)
	}
	return d
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
	handlers := make([]Handler, len(d.subscribers[event.Topic]))
	copy(handlers, d.subscribers[event.Topic])
	globals := make([]Handler, len(d.subscribers[Topic("*")]))
	copy(globals, d.subscribers[Topic("*")])
	d.mu.RUnlock()

	all := append(handlers, globals...)

	if d.async {
		for _, h := range all {
			go func(handler Handler) {
				if err := handler(ctx, event); err != nil {
					if d.errHandler != nil {
						d.errHandler(err)
					}
				}
			}(h)
		}
		return nil
	}

	for _, h := range all {
		if err := h(ctx, event); err != nil {
			continue
		}
	}

	return nil
}
