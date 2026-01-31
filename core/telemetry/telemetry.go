package telemetry

import (
	"context"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc"
	"go.opentelemetry.io/otel/exporters/prometheus"
	"go.opentelemetry.io/otel/metric"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.24.0"
	"go.opentelemetry.io/otel/trace"
)

// Config holds the telemetry configuration.
type Config struct {
	// ServiceName is the name of the service (e.g., "kayan").
	ServiceName string

	// ServiceVersion is the version of the service.
	ServiceVersion string

	// Environment is the deployment environment (e.g., "production").
	Environment string

	// OTLPEndpoint is the OTLP exporter endpoint for traces.
	// Leave empty to disable trace export.
	OTLPEndpoint string

	// SamplingRate is the trace sampling rate (0.0-1.0).
	SamplingRate float64

	// Enabled determines if telemetry is active.
	Enabled bool
}

// DefaultConfig returns a default telemetry configuration.
func DefaultConfig() Config {
	return Config{
		ServiceName:    "kayan",
		ServiceVersion: "1.0.0",
		Environment:    "development",
		SamplingRate:   1.0,
		Enabled:        true,
	}
}

// Provider manages OpenTelemetry tracer and meter providers.
type Provider struct {
	config         Config
	tracerProvider *sdktrace.TracerProvider
	meterProvider  *sdkmetric.MeterProvider
	tracer         trace.Tracer
	meter          metric.Meter

	// Metrics
	loginCounter        metric.Int64Counter
	registrationCounter metric.Int64Counter
	mfaCounter          metric.Int64Counter
	rateLimitCounter    metric.Int64Counter
	lockoutCounter      metric.Int64Counter
	authDuration        metric.Float64Histogram
	activeSessions      metric.Int64UpDownCounter
}

// NewProvider creates a new telemetry provider.
func NewProvider(cfg Config) (*Provider, error) {
	if !cfg.Enabled {
		return &Provider{config: cfg}, nil
	}

	p := &Provider{config: cfg}

	// Create resource
	res, err := resource.Merge(
		resource.Default(),
		resource.NewWithAttributes(
			semconv.SchemaURL,
			semconv.ServiceName(cfg.ServiceName),
			semconv.ServiceVersion(cfg.ServiceVersion),
			attribute.String("environment", cfg.Environment),
		),
	)
	if err != nil {
		return nil, err
	}

	// Setup tracing
	if err := p.setupTracing(res); err != nil {
		return nil, err
	}

	// Setup metrics
	if err := p.setupMetrics(res); err != nil {
		return nil, err
	}

	// Initialize metrics instruments
	if err := p.initMetrics(); err != nil {
		return nil, err
	}

	return p, nil
}

func (p *Provider) setupTracing(res *resource.Resource) error {
	var sampler sdktrace.Sampler
	if p.config.SamplingRate >= 1.0 {
		sampler = sdktrace.AlwaysSample()
	} else if p.config.SamplingRate <= 0 {
		sampler = sdktrace.NeverSample()
	} else {
		sampler = sdktrace.TraceIDRatioBased(p.config.SamplingRate)
	}

	opts := []sdktrace.TracerProviderOption{
		sdktrace.WithSampler(sampler),
		sdktrace.WithResource(res),
	}

	// Add OTLP exporter if configured
	if p.config.OTLPEndpoint != "" {
		exporter, err := otlptracegrpc.New(
			context.Background(),
			otlptracegrpc.WithEndpoint(p.config.OTLPEndpoint),
			otlptracegrpc.WithInsecure(),
		)
		if err != nil {
			return err
		}
		opts = append(opts, sdktrace.WithBatcher(exporter))
	}

	p.tracerProvider = sdktrace.NewTracerProvider(opts...)
	otel.SetTracerProvider(p.tracerProvider)

	p.tracer = p.tracerProvider.Tracer(p.config.ServiceName)

	return nil
}

func (p *Provider) setupMetrics(res *resource.Resource) error {
	exporter, err := prometheus.New()
	if err != nil {
		return err
	}

	p.meterProvider = sdkmetric.NewMeterProvider(
		sdkmetric.WithResource(res),
		sdkmetric.WithReader(exporter),
	)
	otel.SetMeterProvider(p.meterProvider)

	p.meter = p.meterProvider.Meter(p.config.ServiceName)

	return nil
}

func (p *Provider) initMetrics() error {
	var err error

	// Login counter
	p.loginCounter, err = p.meter.Int64Counter(
		"kayan.login.total",
		metric.WithDescription("Total number of login attempts"),
		metric.WithUnit("1"),
	)
	if err != nil {
		return err
	}

	// Registration counter
	p.registrationCounter, err = p.meter.Int64Counter(
		"kayan.registration.total",
		metric.WithDescription("Total number of registration attempts"),
		metric.WithUnit("1"),
	)
	if err != nil {
		return err
	}

	// MFA counter
	p.mfaCounter, err = p.meter.Int64Counter(
		"kayan.mfa.total",
		metric.WithDescription("Total number of MFA attempts"),
		metric.WithUnit("1"),
	)
	if err != nil {
		return err
	}

	// Rate limit counter
	p.rateLimitCounter, err = p.meter.Int64Counter(
		"kayan.rate_limit.total",
		metric.WithDescription("Total number of rate limit events"),
		metric.WithUnit("1"),
	)
	if err != nil {
		return err
	}

	// Lockout counter
	p.lockoutCounter, err = p.meter.Int64Counter(
		"kayan.lockout.total",
		metric.WithDescription("Total number of lockout events"),
		metric.WithUnit("1"),
	)
	if err != nil {
		return err
	}

	// Auth duration histogram
	p.authDuration, err = p.meter.Float64Histogram(
		"kayan.auth.duration",
		metric.WithDescription("Authentication duration in seconds"),
		metric.WithUnit("s"),
	)
	if err != nil {
		return err
	}

	// Active sessions gauge
	p.activeSessions, err = p.meter.Int64UpDownCounter(
		"kayan.sessions.active",
		metric.WithDescription("Number of active sessions"),
		metric.WithUnit("1"),
	)
	if err != nil {
		return err
	}

	return nil
}

// Shutdown gracefully shuts down the telemetry providers.
func (p *Provider) Shutdown(ctx context.Context) error {
	if p.tracerProvider != nil {
		if err := p.tracerProvider.Shutdown(ctx); err != nil {
			return err
		}
	}
	if p.meterProvider != nil {
		if err := p.meterProvider.Shutdown(ctx); err != nil {
			return err
		}
	}
	return nil
}

// Tracer returns the tracer instance.
func (p *Provider) Tracer() trace.Tracer {
	if p.tracer == nil {
		return otel.Tracer(p.config.ServiceName)
	}
	return p.tracer
}

// Meter returns the meter instance.
func (p *Provider) Meter() metric.Meter {
	if p.meter == nil {
		return otel.Meter(p.config.ServiceName)
	}
	return p.meter
}

// ---- Metric Recording Methods ----

// RecordLogin records a login attempt.
func (p *Provider) RecordLogin(ctx context.Context, strategy string, success bool, tenant string) {
	if p.loginCounter == nil {
		return
	}
	status := "success"
	if !success {
		status = "failure"
	}
	p.loginCounter.Add(ctx, 1,
		metric.WithAttributes(
			attribute.String("status", status),
			attribute.String("strategy", strategy),
			attribute.String("tenant", tenant),
		),
	)
}

// RecordRegistration records a registration attempt.
func (p *Provider) RecordRegistration(ctx context.Context, strategy string, success bool, tenant string) {
	if p.registrationCounter == nil {
		return
	}
	status := "success"
	if !success {
		status = "failure"
	}
	p.registrationCounter.Add(ctx, 1,
		metric.WithAttributes(
			attribute.String("status", status),
			attribute.String("strategy", strategy),
			attribute.String("tenant", tenant),
		),
	)
}

// RecordMFA records an MFA attempt.
func (p *Provider) RecordMFA(ctx context.Context, mfaType string, success bool) {
	if p.mfaCounter == nil {
		return
	}
	status := "success"
	if !success {
		status = "failure"
	}
	p.mfaCounter.Add(ctx, 1,
		metric.WithAttributes(
			attribute.String("status", status),
			attribute.String("type", mfaType),
		),
	)
}

// RecordRateLimit records a rate limit event.
func (p *Provider) RecordRateLimit(ctx context.Context, action string, key string) {
	if p.rateLimitCounter == nil {
		return
	}
	p.rateLimitCounter.Add(ctx, 1,
		metric.WithAttributes(
			attribute.String("action", action),
			attribute.String("key", key),
		),
	)
}

// RecordLockout records a lockout event.
func (p *Provider) RecordLockout(ctx context.Context, action string) {
	if p.lockoutCounter == nil {
		return
	}
	p.lockoutCounter.Add(ctx, 1,
		metric.WithAttributes(
			attribute.String("action", action),
		),
	)
}

// RecordAuthDuration records authentication duration.
func (p *Provider) RecordAuthDuration(ctx context.Context, strategy string, duration time.Duration) {
	if p.authDuration == nil {
		return
	}
	p.authDuration.Record(ctx, duration.Seconds(),
		metric.WithAttributes(
			attribute.String("strategy", strategy),
		),
	)
}

// SessionCreated increments the active session count.
func (p *Provider) SessionCreated(ctx context.Context, tenant string) {
	if p.activeSessions == nil {
		return
	}
	p.activeSessions.Add(ctx, 1,
		metric.WithAttributes(
			attribute.String("tenant", tenant),
		),
	)
}

// SessionDestroyed decrements the active session count.
func (p *Provider) SessionDestroyed(ctx context.Context, tenant string) {
	if p.activeSessions == nil {
		return
	}
	p.activeSessions.Add(ctx, -1,
		metric.WithAttributes(
			attribute.String("tenant", tenant),
		),
	)
}
