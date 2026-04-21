package events

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestDispatcher_Subscribe_Dispatch(t *testing.T) {
	d := NewDispatcher()
	var called bool
	d.Subscribe(TopicLoginSuccess, func(ctx context.Context, event Event) error {
		called = true
		return nil
	})

	d.Dispatch(context.Background(), Event{Topic: TopicLoginSuccess})
	if !called {
		t.Fatal("handler not called")
	}
}

func TestDispatcher_Wildcard(t *testing.T) {
	d := NewDispatcher()
	var count int
	d.Subscribe(Topic("*"), func(ctx context.Context, event Event) error {
		count++
		return nil
	})

	d.Dispatch(context.Background(), Event{Topic: TopicLoginSuccess})
	d.Dispatch(context.Background(), Event{Topic: TopicIdentityCreated})
	if count != 2 {
		t.Fatalf("expected wildcard handler called 2 times, got %d", count)
	}
}

func TestDispatcher_Async(t *testing.T) {
	d := NewDispatcher(WithAsync())
	var wg sync.WaitGroup
	wg.Add(1)

	d.Subscribe(TopicLoginSuccess, func(ctx context.Context, event Event) error {
		defer wg.Done()
		return nil
	})

	d.Dispatch(context.Background(), Event{Topic: TopicLoginSuccess})

	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		// success
	case <-time.After(2 * time.Second):
		t.Fatal("async handler not called within timeout")
	}
}

func TestDispatcher_Async_ErrorHandler(t *testing.T) {
	var capturedErr atomic.Value

	d := NewDispatcher(
		WithAsync(),
		WithErrorHandler(func(err error) {
			capturedErr.Store(err)
		}),
	)

	testErr := errors.New("handler failed")
	d.Subscribe(TopicLoginFailure, func(ctx context.Context, event Event) error {
		return testErr
	})

	d.Dispatch(context.Background(), Event{Topic: TopicLoginFailure})

	// Wait for async handler
	time.Sleep(100 * time.Millisecond)

	v := capturedErr.Load()
	if v == nil {
		t.Fatal("error handler not called")
	}
	if v.(error) != testErr {
		t.Fatalf("expected %v, got %v", testErr, v)
	}
}

func TestDispatcher_Concurrent(t *testing.T) {
	d := NewDispatcher()
	var count atomic.Int64

	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(2)
		go func() {
			defer wg.Done()
			d.Subscribe(TopicLoginSuccess, func(ctx context.Context, event Event) error {
				count.Add(1)
				return nil
			})
		}()
		go func() {
			defer wg.Done()
			d.Dispatch(context.Background(), Event{Topic: TopicLoginSuccess})
		}()
	}
	wg.Wait()

	// Just verify no panics/races occurred — count is non-deterministic
	if count.Load() < 0 {
		t.Fatal("impossible")
	}
}
