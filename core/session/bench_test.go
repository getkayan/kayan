package session

import (
	"context"
	"testing"
	"time"
)

func BenchmarkJWTCreate(b *testing.B) {
	ctx := context.Background()
	strategy := NewHS256Strategy("benchmark-secret-key-32bytes!!", 15*time.Minute)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		strategy.Create(ctx, "session-1", "user-1")
	}
}

func BenchmarkJWTValidate(b *testing.B) {
	ctx := context.Background()
	strategy := NewHS256Strategy("benchmark-secret-key-32bytes!!", 15*time.Minute)
	sess, _ := strategy.Create(ctx, "session-1", "user-1")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		strategy.Validate(ctx, sess.ID)
	}
}
