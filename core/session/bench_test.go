package session

import (
	"testing"
	"time"
)

func BenchmarkJWTCreate(b *testing.B) {
	strategy := NewHS256Strategy("benchmark-secret-key-32bytes!!", 15*time.Minute)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		strategy.Create("session-1", "user-1")
	}
}

func BenchmarkJWTValidate(b *testing.B) {
	strategy := NewHS256Strategy("benchmark-secret-key-32bytes!!", 15*time.Minute)
	sess, _ := strategy.Create("session-1", "user-1")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		strategy.Validate(sess.ID)
	}
}
