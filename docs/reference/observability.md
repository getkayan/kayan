# Observability API Reference

The optional `kayan-observability` module supplies environment configuration,
structured logging, OpenTelemetry tracing, and metrics. It is separate from
`core` so applications that do not use OpenTelemetry, Zap, or Viper do not pay
for those dependency trees.

```bash
go get github.com/getkayan/kayan/kayan-observability@v0.3.0
```

The module contains three independent packages:

- [`config`](#package-config) loads a small host-application configuration from
  environment variables;
- [`logger`](#package-logger) initializes a process-wide Zap logger;
- [`telemetry`](#package-telemetry) creates OpenTelemetry providers and records
  IAM metrics and spans.

You can import any one without using the others. None of them is required by
Kayan's authentication or authorization managers.

## Package `config`

```go
import "github.com/getkayan/kayan/kayan-observability/config"
```

### Types

```go
type Config struct {
    DBType          string                  `mapstructure:"DB_TYPE"`
    DSN             string                  `mapstructure:"DSN"`
    SkipAutoMigrate bool                    `mapstructure:"SKIP_AUTO_MIGRATE"`
    LogLevel        string                  `mapstructure:"LOG_LEVEL"`
    OIDCProviders   map[string]OIDCProvider `mapstructure:"OIDC_PROVIDERS"`
}

type OIDCProvider struct {
    Issuer       string `mapstructure:"issuer"`
    ClientID     string `mapstructure:"client_id"`
    ClientSecret string `mapstructure:"client_secret"`
    RedirectURL  string `mapstructure:"redirect_url"`
}
```

`Config` is application configuration, not an IAM storage contract. `DBType`
and `DSN` describe the database the host application intends to open;
`LoadConfig` does not open it or run migrations.

### `LoadConfig`

```go
func LoadConfig() (*Config, error)
```

Reads environment variables through Viper and applies these defaults:

| Variable | Default | Meaning |
|---|---|---|
| `DB_TYPE` | `sqlite` | Host application's database selector |
| `DSN` | `kayan.db` | Database connection string |
| `SKIP_AUTO_MIGRATE` | `false` | Whether the host skips automatic development migrations |
| `LOG_LEVEL` | `info` | Zap level passed to `logger.InitLogger` |

Provider configuration maps to `OIDCProviders`. Environment keys use
underscores in place of Viper's nested-key separator:

```text
OIDC_PROVIDERS_GOOGLE_ISSUER=https://accounts.google.com
OIDC_PROVIDERS_GOOGLE_CLIENT_ID=...
OIDC_PROVIDERS_GOOGLE_CLIENT_SECRET=...
OIDC_PROVIDERS_GOOGLE_REDIRECT_URL=https://app.example.com/callback
```

`ClientSecret` is sensitive. Do not log the loaded structure, return it from a
configuration endpoint, or persist it in an audit event.

```go
cfg, err := config.LoadConfig()
if err != nil {
    return fmt.Errorf("load configuration: %w", err)
}
```

`LoadConfig` uses Viper's process-wide default instance. Load configuration
during startup rather than concurrently changing Viper settings at runtime.

## Package `logger`

```go
import "github.com/getkayan/kayan/kayan-observability/logger"
```

### `Log`

```go
var Log = zap.NewNop()
```

`Log` is never nil. Before initialization it discards entries, allowing startup
code to log without risking a nil-pointer panic.

### `InitLogger`

```go
func InitLogger(level string) error
```

Builds a production Zap logger with ISO-8601 timestamps and assigns it to
`Log`. Supported Zap levels include `debug`, `info`, `warn`, and `error`.
Unrecognized values fall back to `info`. If construction fails, the previous
logger remains installed and the error is returned.

Initialize once during process startup, before worker goroutines begin using
the logger:

```go
if err := logger.InitLogger(cfg.LogLevel); err != nil {
    return fmt.Errorf("initialize logger: %w", err)
}
defer logger.Log.Sync() // decide how your host reports any flush error

logger.Log.Info("login completed",
    zap.String("strategy", "password"),
    zap.String("tenant_id", tenantID),
)
```

Never attach passwords, session tokens, authorization codes, recovery codes, or
credential hashes as Zap fields. Prefer stable internal IDs over email addresses
or usernames.

## Package `telemetry`

```go
import "github.com/getkayan/kayan/kayan-observability/telemetry"
```

### Configuration

```go
type Config struct {
    ServiceName    string
    ServiceVersion string
    Environment    string
    OTLPEndpoint   string
    InsecureOTLP   bool
    SamplingRate   float64
    Enabled        bool
}

func DefaultConfig() Config
```

`DefaultConfig` returns:

```go
telemetry.Config{
    ServiceName:    "kayan",
    ServiceVersion: "1.0.0",
    Environment:    "development",
    SamplingRate:   1.0,
    Enabled:        true,
}
```

Set `ServiceVersion` to the host application's version, not the Kayan module
version. `SamplingRate <= 0` samples no spans, `>= 1` samples every span, and a
value between them uses trace-ID ratio sampling.

When `OTLPEndpoint` is empty, no OTLP trace exporter is installed. When it is
set, transport uses TLS unless `InsecureOTLP` is true. Use plaintext OTLP only
on a trusted development network.

### Provider lifecycle

```go
type Provider struct {
    // Has unexported fields.
}

func NewProvider(cfg Config) (*Provider, error)
func (p *Provider) Shutdown(ctx context.Context) error
func (p *Provider) Tracer() trace.Tracer
func (p *Provider) Meter() metric.Meter
```

`NewProvider` creates SDK tracer and meter providers, installs them as the
OpenTelemetry process globals, creates the Prometheus reader, and initializes
Kayan's instruments. Create one provider during startup and shut it down with a
bounded context:

```go
cfg := telemetry.DefaultConfig()
cfg.ServiceName = "orders-api"
cfg.ServiceVersion = buildVersion
cfg.Environment = "production"
cfg.OTLPEndpoint = "otel-collector.internal:4317"
cfg.SamplingRate = 0.1

provider, err := telemetry.NewProvider(cfg)
if err != nil {
    return fmt.Errorf("initialize telemetry: %w", err)
}

shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
defer cancel()
defer provider.Shutdown(shutdownCtx)
```

The provider changes OpenTelemetry's global tracer and meter providers. If the
host application already owns those globals, integrate at the application
boundary rather than constructing a second Kayan provider.

With `Enabled: false`, metric recording methods are no-ops and `Shutdown` has
nothing to close. `Tracer` and `Meter` fall back to the current OpenTelemetry
globals, so manual spans may still be recorded if the host installed its own
global providers.

### Event-driven metrics

```go
func Subscribe(dispatcher events.Dispatcher, provider *Provider)
```

Subscribes metrics handlers to Kayan domain events. This is the preferred
integration because login and session managers already emit those events:

```go
dispatcher := events.NewDispatcher()
telemetry.Subscribe(dispatcher, provider)

login := flow.NewLoginManager(
    repo,
    func() any { return &User{} },
    flow.WithLoginDispatcher(dispatcher),
)
```

`Subscribe(nil, provider)` and `Subscribe(dispatcher, nil)` are safe no-ops.
Rate-limit metrics deliberately omit the limiter key to avoid attacker-driven
cardinality and leaking attempted usernames into the metrics backend.

The handlers record:

| Instrument | Type | Attributes |
|---|---|---|
| `kayan.login.total` | counter | `status`, `strategy`, `tenant` |
| `kayan.registration.total` | counter | `status`, `strategy`, `tenant` |
| `kayan.mfa.total` | counter | `status`, `type` |
| `kayan.rate_limit.total` | counter | `action`, `key` |
| `kayan.lockout.total` | counter | `action` |
| `kayan.auth.duration` | histogram, seconds | `strategy` |
| `kayan.sessions.active` | up/down counter | `tenant` |
| `kayan.governance.decisions` | counter | `tenant`, `operation`, `scope`, `kind`, `outcome` |
| `kayan.governance.in_flight` | up/down counter | `tenant`, `operation` |
| `kayan.governance.operation.duration` | histogram, seconds | `tenant`, `operation` |

### Tenant resource-governance metrics

```go
func (p *Provider) TenantGovernorHooks() tenant.GovernorHooks
```

Pass these hooks to `tenant.WithGovernorHooks` when constructing a governor.
Allowed admissions increment `in_flight`; permit release decrements it and
records duration. Decisions distinguish `allowed`, policy `limited`, and
backend/configuration `error` outcomes.

A nil or disabled provider returns empty hooks. Tenant labels are bounded by
the set of validated tenants, but can still be expensive at large scale. Drop
or aggregate the tenant attribute in the OpenTelemetry Collector when the
metrics backend cannot sustain one series per tenant and operation. Keep
high-cardinality billing records in a dedicated usage store.

### Direct metric recording

Applications that do not use a dispatcher can call the same instruments
directly:

```go
func (p *Provider) RecordLogin(ctx context.Context, strategy string, success bool, tenant string)
func (p *Provider) RecordRegistration(ctx context.Context, strategy string, success bool, tenant string)
func (p *Provider) RecordMFA(ctx context.Context, mfaType string, success bool)
func (p *Provider) RecordRateLimit(ctx context.Context, action, key string)
func (p *Provider) RecordLockout(ctx context.Context, action string)
func (p *Provider) RecordAuthDuration(ctx context.Context, strategy string, duration time.Duration)
func (p *Provider) SessionCreated(ctx context.Context, tenant string)
func (p *Provider) SessionDestroyed(ctx context.Context, tenant string)
```

Keep attribute values bounded. In particular, do not pass raw usernames,
emails, IP addresses, or arbitrary URL paths as `strategy`, `tenant`, `action`,
or `key`; each distinct value can create a new metric series.

### Spans

```go
type SpanOptions struct {
    TenantID   string
    IdentityID string
    Strategy   string
    SessionID  string
    IPAddress  string
    UserAgent  string
}

func (p *Provider) StartSpan(ctx context.Context, name string, opts SpanOptions) (context.Context, trace.Span)
```

Only non-empty `SpanOptions` fields become span attributes. The exported keys
are:

```go
const (
    AttrIdentityID = "kayan.identity.id"
    AttrTenantID   = "kayan.tenant.id"
    AttrStrategy   = "kayan.auth.strategy"
    AttrSessionID  = "kayan.session.id"
    AttrIPAddress  = "kayan.client.ip"
    AttrUserAgent  = "kayan.client.user_agent"
)
```

Convenience methods apply stable Kayan span names:

```go
func (p *Provider) SpanLogin(ctx context.Context, identifier, strategy string) (context.Context, trace.Span)
func (p *Provider) SpanRegistration(ctx context.Context, strategy string) (context.Context, trace.Span)
func (p *Provider) SpanMFA(ctx context.Context, mfaType, identityID string) (context.Context, trace.Span)
func (p *Provider) SpanOIDC(ctx context.Context, provider string) (context.Context, trace.Span)
func (p *Provider) SpanSAML(ctx context.Context, idpID string) (context.Context, trace.Span)
func (p *Provider) SpanWebAuthn(ctx context.Context, operation string) (context.Context, trace.Span)
func (p *Provider) SpanSessionCreate(ctx context.Context, identityID string) (context.Context, trace.Span)
func (p *Provider) SpanSessionValidate(ctx context.Context, sessionID string) (context.Context, trace.Span)
func (p *Provider) SpanSessionRefresh(ctx context.Context, sessionID string) (context.Context, trace.Span)
func (p *Provider) SpanPolicyCheck(ctx context.Context, action, resource string) (context.Context, trace.Span)
func (p *Provider) SpanRateLimit(ctx context.Context, key string) (context.Context, trace.Span)
```

`SpanLogin` stores `identifier` under `kayan.identity.id`. Pass an internal ID
when possible; passing an email address copies personal data into the tracing
backend. Apply the same rule to rate-limit keys, provider IDs, and resource
names.

Always continue with the returned context so child spans inherit it:

```go
ctx, span := provider.SpanLogin(ctx, userID, "password")
defer telemetry.EndSpan(span, err)

identity, err := login.Authenticate(ctx, "password", email, password)
```

### Span helpers

```go
func SetSpanError(span trace.Span, err error)
func SetSpanSuccess(span trace.Span)
func AddSpanEvent(span trace.Span, name string, attrs ...attribute.KeyValue)
func EndSpan(span trace.Span, err error)
```

All helpers accept a nil span. `SetSpanError` records the error and marks the
span failed; `SetSpanSuccess` marks it successful; `EndSpan` applies the status
and ends it. Errors may contain sensitive details, so sanitize errors before
sending them to a telemetry backend when their messages can contain user input.

## Related references

- [Configuration reference](./configuration.md)
- [Core events and audit API](./core.md)
- [Operations guide](../operations/README.md)
- [Exhaustive Go API index](./go-api.md)
