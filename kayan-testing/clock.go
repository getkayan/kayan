package kayantesting

import (
	"sync"
	"time"

	"github.com/getkayan/kayan/core/domain"
)

// FakeClock is a [domain.Clock] whose time only moves when told.
//
// Not for production use. It exists so validity windows can be tested at their
// exact boundary rather than by sleeping:
//
//	clock := kayantesting.NewFakeClock(time.Now())
//	token := issue(clock.Now())
//	clock.Advance(ttl - time.Nanosecond)
//	// still valid
//	clock.Advance(time.Nanosecond)
//	// now expired
//
// It is safe for concurrent use.
type FakeClock struct {
	mu  sync.RWMutex
	now time.Time
}

var _ domain.Clock = (*FakeClock)(nil)

// NewFakeClock returns a clock fixed at t.
func NewFakeClock(t time.Time) *FakeClock {
	return &FakeClock{now: t}
}

// Now returns the current fake time.
func (c *FakeClock) Now() time.Time {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.now
}

// Advance moves the clock forward by d. A negative d moves it backwards, which
// is useful for testing clock skew.
func (c *FakeClock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
}

// Set moves the clock to t.
func (c *FakeClock) Set(t time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = t
}
