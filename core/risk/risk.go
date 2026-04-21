// Package risk provides adaptive risk scoring for authentication and security flows.
//
// The package is transport-agnostic and storage-agnostic. Applications feed signals
// such as failed attempts, device novelty, or location anomalies into a Rule-based
// Engine, then use the resulting score and level to decide whether to allow, step up,
// or block the action.
//
// # Example Usage
//
//	engine := risk.NewEngine()
//	engine.Register(risk.NewFailedAttemptsRule(3, 30))
//	engine.Register(risk.NewNewDeviceRule(15))
//
//	assessment, _ := engine.Assess(context.Background(), &risk.Input{
//	    FailedAttempts: 4,
//	    NewDevice:      true,
//	})
//
//	if assessment.Level == risk.LevelHigh {
//	    // Require MFA or block the action.
//	}
package risk

import (
	"context"
	"sync"
	"time"
)

// Level categorizes the severity of an assessment.
type Level string

const (
	LevelLow      Level = "low"
	LevelMedium   Level = "medium"
	LevelHigh     Level = "high"
	LevelCritical Level = "critical"
)

// Input contains transport-neutral and schema-neutral data for a risk decision.
type Input struct {
	ActorID        string
	TenantID       string
	IPAddress      string
	UserAgent      string
	DeviceID       string
	GeoCountry     string
	GeoRegion      string
	GeoCity        string
	FailedAttempts int
	NewDevice      bool
	ImpossibleTrip bool
	GeoChanged     bool
	Attributes     map[string]any
}

// Signal captures the outcome of a single rule evaluation.
type Signal struct {
	Name      string         `json:"name"`
	Triggered bool           `json:"triggered"`
	Weight    int            `json:"weight"`
	Reason    string         `json:"reason,omitempty"`
	Metadata  map[string]any `json:"metadata,omitempty"`
}

// Assessment is the final result of evaluating risk rules.
type Assessment struct {
	Score     int       `json:"score"`
	Level     Level     `json:"level"`
	Signals   []Signal  `json:"signals"`
	Reasons   []string  `json:"reasons,omitempty"`
	Timestamp time.Time `json:"timestamp"`
}

// Rule evaluates one piece of risk logic.
type Rule interface {
	Name() string
	Evaluate(ctx context.Context, input *Input) Signal
}

// RuleFunc adapts a function into a Rule.
type RuleFunc struct {
	RuleName string
	Fn       func(ctx context.Context, input *Input) Signal
}

func (r RuleFunc) Name() string { return r.RuleName }

func (r RuleFunc) Evaluate(ctx context.Context, input *Input) Signal {
	if r.Fn == nil {
		return Signal{Name: r.RuleName}
	}
	result := r.Fn(ctx, input)
	if result.Name == "" {
		result.Name = r.RuleName
	}
	return result
}

// Thresholds controls how numeric scores map to risk levels.
type Thresholds struct {
	Medium   int
	High     int
	Critical int
}

// normalize returns safe, ordered thresholds.
func (t Thresholds) normalize() Thresholds {
	if t.Medium <= 0 {
		t.Medium = 20
	}
	if t.High <= t.Medium {
		t.High = 50
	}
	if t.Critical <= t.High {
		t.Critical = 80
	}
	return t
}

// Engine evaluates registered rules and produces a risk assessment.
type Engine struct {
	mu         sync.RWMutex
	rules      []Rule
	thresholds Thresholds
}

// Option configures an Engine.
type Option func(*Engine)

// NewEngine creates a risk engine with sensible default thresholds.
func NewEngine(opts ...Option) *Engine {
	e := &Engine{
		thresholds: Thresholds{Medium: 20, High: 50, Critical: 80},
	}
	for _, opt := range opts {
		opt(e)
	}
	e.thresholds = e.thresholds.normalize()
	return e
}

// WithThresholds overrides the level thresholds.
func WithThresholds(thresholds Thresholds) Option {
	return func(e *Engine) {
		e.thresholds = thresholds.normalize()
	}
}

// Register adds a rule to the engine.
func (e *Engine) Register(rule Rule) {
	if rule == nil {
		return
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	e.rules = append(e.rules, rule)
}

// RegisterFunc adds a function-backed rule to the engine.
func (e *Engine) RegisterFunc(name string, fn func(ctx context.Context, input *Input) Signal) {
	e.Register(RuleFunc{RuleName: name, Fn: fn})
}

// Assess evaluates all rules and returns a normalized assessment.
func (e *Engine) Assess(ctx context.Context, input *Input) (*Assessment, error) {
	e.mu.RLock()
	rules := make([]Rule, len(e.rules))
	copy(rules, e.rules)
	thresholds := e.thresholds
	e.mu.RUnlock()

	assessment := &Assessment{
		Level:     LevelLow,
		Signals:   make([]Signal, 0, len(rules)),
		Reasons:   make([]string, 0, len(rules)),
		Timestamp: time.Now(),
	}

	for _, rule := range rules {
		signal := rule.Evaluate(ctx, input)
		if signal.Name == "" {
			signal.Name = rule.Name()
		}
		assessment.Signals = append(assessment.Signals, signal)
		if !signal.Triggered {
			continue
		}
		assessment.Score += signal.Weight
		if signal.Reason != "" {
			assessment.Reasons = append(assessment.Reasons, signal.Reason)
		}
	}

	if assessment.Score > 100 {
		assessment.Score = 100
	}
	assessment.Level = thresholds.levelFor(assessment.Score)

	return assessment, nil
}

func (t Thresholds) levelFor(score int) Level {
	switch {
	case score >= t.Critical:
		return LevelCritical
	case score >= t.High:
		return LevelHigh
	case score >= t.Medium:
		return LevelMedium
	default:
		return LevelLow
	}
}

type thresholdRule struct {
	name      string
	weight    int
	reason    string
	threshold int
	valueFn   func(input *Input) int
}

func (r *thresholdRule) Name() string { return r.name }

func (r *thresholdRule) Evaluate(ctx context.Context, input *Input) Signal {
	value := 0
	if r.valueFn != nil && input != nil {
		value = r.valueFn(input)
	}
	return Signal{
		Name:      r.name,
		Triggered: value >= r.threshold,
		Weight:    r.weight,
		Reason:    r.reason,
		Metadata:  map[string]any{"value": value, "threshold": r.threshold},
	}
}

type boolRule struct {
	name    string
	weight  int
	reason  string
	checkFn func(input *Input) bool
}

func (r *boolRule) Name() string { return r.name }

func (r *boolRule) Evaluate(ctx context.Context, input *Input) Signal {
	triggered := false
	if r.checkFn != nil && input != nil {
		triggered = r.checkFn(input)
	}
	return Signal{
		Name:      r.name,
		Triggered: triggered,
		Weight:    r.weight,
		Reason:    r.reason,
	}
}

// NewFailedAttemptsRule increases risk when failed attempts meet or exceed the threshold.
func NewFailedAttemptsRule(threshold, weight int) Rule {
	return &thresholdRule{
		name:      "failed_attempts",
		weight:    weight,
		threshold: threshold,
		reason:    "failed attempts exceed threshold",
		valueFn: func(input *Input) int {
			return input.FailedAttempts
		},
	}
}

// NewNewDeviceRule increases risk when the attempt comes from a new device.
func NewNewDeviceRule(weight int) Rule {
	return &boolRule{
		name:   "new_device",
		weight: weight,
		reason: "authentication from a new device",
		checkFn: func(input *Input) bool {
			return input.NewDevice
		},
	}
}

// NewImpossibleTripRule increases risk when travel velocity is implausible.
func NewImpossibleTripRule(weight int) Rule {
	return &boolRule{
		name:   "impossible_trip",
		weight: weight,
		reason: "impossible travel detected",
		checkFn: func(input *Input) bool {
			return input.ImpossibleTrip
		},
	}
}

// NewGeoChangedRule increases risk when geography changed unexpectedly.
func NewGeoChangedRule(weight int) Rule {
	return &boolRule{
		name:   "geo_changed",
		weight: weight,
		reason: "geographic location changed",
		checkFn: func(input *Input) bool {
			return input.GeoChanged
		},
	}
}
