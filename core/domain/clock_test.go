package domain

import (
	"testing"
	"time"
)

func TestClockFuncAdaptsAFunction(t *testing.T) {
	fixed := time.Date(2026, 8, 4, 12, 0, 0, 0, time.UTC)
	clock := ClockFunc(func() time.Time { return fixed })

	if got := clock.Now(); !got.Equal(fixed) {
		t.Errorf("Now() = %v, want %v", got, fixed)
	}
}

func TestSystemClockAdvances(t *testing.T) {
	first := SystemClock.Now()
	if first.IsZero() {
		t.Fatal("SystemClock returned the zero time")
	}
	if second := SystemClock.Now(); second.Before(first) {
		t.Errorf("clock moved backwards: %v then %v", first, second)
	}
}

// TestClockOrDefault covers the constructor path: omitting the option, or
// passing a nil Clock explicitly, must yield a working clock rather than a
// nil-pointer panic at the first expiry check.
func TestClockOrDefault(t *testing.T) {
	if got := ClockOrDefault(nil); got == nil {
		t.Fatal("ClockOrDefault(nil) returned nil")
	}
	if ClockOrDefault(nil).Now().IsZero() {
		t.Error("default clock returned the zero time")
	}

	fixed := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	custom := ClockFunc(func() time.Time { return fixed })
	if got := ClockOrDefault(custom).Now(); !got.Equal(fixed) {
		t.Errorf("ClockOrDefault did not preserve the supplied clock: got %v", got)
	}
}

// TestClockDrivesExpiryDeterministically demonstrates the property the whole
// interface exists for: a validity window can be tested at its exact boundary
// without sleeping.
func TestClockDrivesExpiryDeterministically(t *testing.T) {
	issued := time.Date(2026, 8, 4, 12, 0, 0, 0, time.UTC)
	expiry := issued.Add(time.Hour)

	now := issued
	clock := ClockFunc(func() time.Time { return now })

	expired := func() bool { return !clock.Now().Before(expiry) }

	if expired() {
		t.Error("token reported expired at issue time")
	}

	now = expiry.Add(-time.Nanosecond)
	if expired() {
		t.Error("token reported expired one nanosecond before expiry")
	}

	now = expiry
	if !expired() {
		t.Error("token not reported expired at exactly the expiry instant")
	}
}
