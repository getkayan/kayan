package domain

import "time"

// Clock reports the current time.
//
// Security decisions that depend on time — token expiry, assertion validity
// windows, lockout durations — read the clock through this interface so tests
// can drive them deterministically instead of sleeping.
//
// Implementations must be safe for concurrent use.
type Clock interface {
	Now() time.Time
}

// ClockFunc adapts an ordinary function to Clock.
//
//	clock := domain.ClockFunc(func() time.Time { return fixed })
type ClockFunc func() time.Time

// Now calls f.
func (f ClockFunc) Now() time.Time { return f() }

// SystemClock reads wall-clock time. It is the default for every component
// that accepts a Clock.
var SystemClock Clock = ClockFunc(time.Now)

// ClockOrDefault returns c, or SystemClock when c is nil.
//
// Constructors call this so a caller who omits the option — or passes a nil
// Clock explicitly — gets working behavior instead of a panic.
func ClockOrDefault(c Clock) Clock {
	if c == nil {
		return SystemClock
	}
	return c
}
