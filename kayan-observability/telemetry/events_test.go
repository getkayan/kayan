package telemetry

import (
	"context"
	"testing"

	"github.com/getkayan/kayan/core/events"
	"github.com/getkayan/kayan/core/identity"
)

// recordingDispatcher captures the topics Subscribe registered for, so a test
// can assert the wiring without standing up an OpenTelemetry pipeline.
type recordingDispatcher struct {
	handlers map[events.Topic][]events.Handler
}

func newRecordingDispatcher() *recordingDispatcher {
	return &recordingDispatcher{handlers: make(map[events.Topic][]events.Handler)}
}

func (d *recordingDispatcher) Subscribe(topic events.Topic, handler events.Handler) {
	d.handlers[topic] = append(d.handlers[topic], handler)
}

func (d *recordingDispatcher) Dispatch(ctx context.Context, event events.Event) error {
	for _, h := range d.handlers[event.Topic] {
		if err := h(ctx, event); err != nil {
			return err
		}
	}
	return nil
}

// TestSubscribeCoversTheSecuritySignals pins the topics an operator needs to
// see. A telemetry package that silently stops reporting lockouts is worse
// than one that was never wired: the dashboard stays green.
func TestSubscribeCoversTheSecuritySignals(t *testing.T) {
	dispatcher := newRecordingDispatcher()
	provider := &Provider{} // no meter configured; recorders are no-ops

	Subscribe(dispatcher, provider)

	for _, topic := range []events.Topic{
		events.TopicLoginSuccess,
		events.TopicLoginFailure,
		events.TopicLoginBlocked,
		events.TopicSecurityRateLimited,
		events.TopicLoginMFARequired,
		events.TopicIdentityCreated,
		events.TopicIdentityFailure,
		events.TopicSessionCreated,
		events.TopicSessionRevoked,
		events.TopicSessionExpired,
		events.TopicLogout,
	} {
		if len(dispatcher.handlers[topic]) == 0 {
			t.Errorf("no handler subscribed for %q", topic)
		}
	}
}

// TestSubscribeSurvivesAnUnconfiguredProvider covers the shape a caller most
// easily gets wrong: telemetry built conditionally, so the provider exists but
// its instruments do not. Dispatching must not panic on the authentication
// path.
func TestSubscribeSurvivesAnUnconfiguredProvider(t *testing.T) {
	dispatcher := newRecordingDispatcher()
	Subscribe(dispatcher, &Provider{})

	ctx := context.Background()
	for topic := range dispatcher.handlers {
		if err := dispatcher.Dispatch(ctx, events.Event{Topic: topic, TenantID: "t1"}); err != nil {
			t.Errorf("dispatching %q returned an error: %v", topic, err)
		}
	}
}

// TestSubscribeIgnoresNilArguments keeps the no-op contract. A caller that
// builds telemetry only in production should not have to guard the call.
func TestSubscribeIgnoresNilArguments(t *testing.T) {
	Subscribe(nil, &Provider{})
	Subscribe(newRecordingDispatcher(), nil)
	Subscribe(nil, nil)
}

// TestStrategyLabelFallsBackToTheTopic keeps metrics from carrying an empty
// label, which renders as an unattributed series nobody can act on.
func TestStrategyLabelFallsBackToTheTopic(t *testing.T) {
	cases := []struct {
		name  string
		event events.Event
		want  string
	}{
		{
			name:  "reads the strategy from metadata",
			event: events.Event{Topic: events.TopicLoginSuccess, Metadata: identity.JSON(`{"strategy":"password"}`)},
			want:  "password",
		},
		{
			name:  "accepts method as an alias",
			event: events.Event{Topic: events.TopicLoginSuccess, Metadata: identity.JSON(`{"method":"totp"}`)},
			want:  "totp",
		},
		{
			name:  "falls back when metadata is absent",
			event: events.Event{Topic: events.TopicLoginFailure},
			want:  string(events.TopicLoginFailure),
		},
		{
			name:  "falls back when metadata is not an object",
			event: events.Event{Topic: events.TopicLoginFailure, Metadata: identity.JSON(`"not-an-object"`)},
			want:  string(events.TopicLoginFailure),
		},
		{
			name:  "falls back when the strategy is empty",
			event: events.Event{Topic: events.TopicLoginFailure, Metadata: identity.JSON(`{"strategy":""}`)},
			want:  string(events.TopicLoginFailure),
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := strategyOf(tc.event); got != tc.want {
				t.Errorf("strategyOf = %q, want %q", got, tc.want)
			}
		})
	}
}
