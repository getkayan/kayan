package risk

import (
	"context"
	"testing"
)

func TestEngine_AssessNoRules(t *testing.T) {
	engine := NewEngine()

	assessment, err := engine.Assess(context.Background(), &Input{})
	if err != nil {
		t.Fatalf("Assess failed: %v", err)
	}
	if assessment.Score != 0 {
		t.Fatalf("expected score 0, got %d", assessment.Score)
	}
	if assessment.Level != LevelLow {
		t.Fatalf("expected low level, got %s", assessment.Level)
	}
}

func TestEngine_AssessThresholds(t *testing.T) {
	engine := NewEngine()
	engine.Register(NewFailedAttemptsRule(3, 30))
	engine.Register(NewNewDeviceRule(25))

	assessment, err := engine.Assess(context.Background(), &Input{FailedAttempts: 3, NewDevice: true})
	if err != nil {
		t.Fatalf("Assess failed: %v", err)
	}
	if assessment.Score != 55 {
		t.Fatalf("expected score 55, got %d", assessment.Score)
	}
	if assessment.Level != LevelHigh {
		t.Fatalf("expected high level, got %s", assessment.Level)
	}
	if len(assessment.Reasons) != 2 {
		t.Fatalf("expected 2 reasons, got %d", len(assessment.Reasons))
	}
}

func TestEngine_AssessCapsScore(t *testing.T) {
	engine := NewEngine()
	engine.Register(NewFailedAttemptsRule(1, 70))
	engine.Register(NewImpossibleTripRule(50))

	assessment, err := engine.Assess(context.Background(), &Input{FailedAttempts: 5, ImpossibleTrip: true})
	if err != nil {
		t.Fatalf("Assess failed: %v", err)
	}
	if assessment.Score != 100 {
		t.Fatalf("expected capped score 100, got %d", assessment.Score)
	}
	if assessment.Level != LevelCritical {
		t.Fatalf("expected critical level, got %s", assessment.Level)
	}
}

func TestEngine_CustomThresholds(t *testing.T) {
	engine := NewEngine(WithThresholds(Thresholds{Medium: 10, High: 20, Critical: 30}))
	engine.Register(NewNewDeviceRule(15))

	assessment, err := engine.Assess(context.Background(), &Input{NewDevice: true})
	if err != nil {
		t.Fatalf("Assess failed: %v", err)
	}
	if assessment.Level != LevelMedium {
		t.Fatalf("expected medium level, got %s", assessment.Level)
	}
}

func TestEngine_RegisterFunc(t *testing.T) {
	engine := NewEngine()
	engine.RegisterFunc("custom", func(ctx context.Context, input *Input) Signal {
		return Signal{Name: "custom", Triggered: true, Weight: 20, Reason: "custom rule"}
	})

	assessment, err := engine.Assess(context.Background(), &Input{})
	if err != nil {
		t.Fatalf("Assess failed: %v", err)
	}
	if assessment.Score != 20 {
		t.Fatalf("expected score 20, got %d", assessment.Score)
	}
	if len(assessment.Signals) != 1 || assessment.Signals[0].Name != "custom" {
		t.Fatalf("expected one custom signal, got %#v", assessment.Signals)
	}
}

func TestBuiltInRules(t *testing.T) {
	ctx := context.Background()
	input := &Input{FailedAttempts: 4, NewDevice: true, ImpossibleTrip: true, GeoChanged: true}

	rules := []Rule{
		NewFailedAttemptsRule(3, 20),
		NewNewDeviceRule(10),
		NewImpossibleTripRule(40),
		NewGeoChangedRule(5),
	}

	for _, rule := range rules {
		signal := rule.Evaluate(ctx, input)
		if !signal.Triggered {
			t.Fatalf("expected %s to trigger", rule.Name())
		}
		if signal.Weight <= 0 {
			t.Fatalf("expected positive weight for %s", rule.Name())
		}
	}
}
