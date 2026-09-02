# Tenant resource governance

Tenant data isolation answers **which rows may be accessed**. Resource
governance answers **how much shared work one tenant may start**. A deployment
needs both: a perfectly scoped query can still monopolize the database pool if
one customer starts thousands of them.

Kayan provides admission control for request handlers, RPC methods, workers,
and message consumers. It does not attempt to schedule CPU, reserve memory, or
partition a database from inside a Go library.

## Limits

```go
type ResourceLimits struct {
    RateLimit        int
    RateWindow       time.Duration
    ConcurrencyLimit int
    LeaseTTL         time.Duration
}

type LimitProvider interface {
    Limits(ctx context.Context, tenantID, operation string) (ResourceLimits, error)
}
```

The rate budget counts admission attempts in a fixed window. The concurrency
budget counts work currently in flight. Zero disables that dimension; negative
limits and enabled limits with durations below one millisecond are rejected.

Use stable operation names such as `login`, `tickets.write`, or
`reports.export`. Operation names become policy and telemetry dimensions, so
never put a user ID, ticket ID, URL, or other unbounded value in them.

`LimitProvider` is evaluated for every admission. It can load limits from a
tenant plan, an application cache, or static configuration. A lookup error
fails closed with `tenant.ErrGovernanceUnavailable`; it never becomes unlimited
capacity.

```go
provider := tenant.LimitProviderFunc(
    func(ctx context.Context, tenantID, operation string) (tenant.ResourceLimits, error) {
        plan, err := plans.ForTenant(ctx, tenantID)
        if err != nil {
            return tenant.ResourceLimits{}, err
        }
        return plan.LimitsFor(operation), nil
    },
)
```

For one policy across all tenants, use `tenant.FixedLimits`.

## Local and distributed enforcement

The in-memory implementations are suitable for tests and one application
process:

```go
governor, err := tenant.NewGovernor(
    tenant.NewMemoryGovernanceRateLimiter(),
    tenant.NewMemoryConcurrencyLimiter(),
    provider,
    tenant.WithGlobalLimitProvider(tenant.FixedLimits{
        ConcurrencyLimit: 200,
        LeaseTTL:         30 * time.Second,
    }),
)
```

Every replica has independent memory, so an in-memory limit of ten permits ten
operations **per replica**. Use Redis when the deployment has more than one
process:

```go notest
governor, err := tenant.NewGovernor(
    redisstore.NewRedisRateLimiter(redisClient, "app:rate:"),
    redisstore.NewRedisConcurrencyLimiter(redisClient, "app:concurrency:"),
    provider,
    tenant.WithGlobalLimitProvider(globalProvider),
    tenant.WithGovernorHooks(otelProvider.TenantGovernorHooks()),
)
```

The Redis concurrency limiter atomically prunes expired leases, checks
capacity, and reserves a unique ownership token. It uses Redis server time, so
clock skew between application replicas cannot shorten or extend leases. The
Redis rate limiter uses the same server clock and random members, preventing
same-millisecond requests from overwriting each other.

## Admission lifecycle

Resolve the tenant first, then acquire capacity before expensive work:

```go
permit, err := governor.Acquire(ctx, "reports.export")
if err != nil {
    return err
}
defer func() {
    cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), 2*time.Second)
    defer cancel()
    _ = permit.Release(cleanup)
}()

return exportReport(ctx)
```

`Acquire` applies the tenant budget before the global budget. A tenant already
over its own limit therefore cannot consume global concurrency. If global
admission fails after tenant capacity was reserved, Kayan releases the partial
tenant lease before returning.

The governor is an admission controller, not a queue scheduler. Configure each
tenant's concurrency limit below the global limit if no single tenant should be
able to occupy all admitted slots. Simultaneous callers race for available
global slots; strict round-robin or weighted fairness requires the per-tenant
worker queues described below.

`Permit.Release` is idempotent. Use a short cleanup context that survives
request cancellation; releasing with an already-cancelled request context
leaves the slot occupied until its TTL.

### Long-running work

Set `LeaseTTL` longer than the normal operation timeout. Jobs that may exceed
it must call `Permit.Renew` before expiry. Stop the job when renewal returns
`tenant.ErrConcurrencyLeaseLost`; continuing would run outside the configured
capacity budget.

Leases expire even if a process crashes, so one dead worker cannot consume a
slot forever. The tradeoff is unavoidable: a lease that is not renewed expires
while its old work may still be running. The host must cancel work on renewal
failure.

## Error mapping

```go
var limitErr *tenant.LimitError
switch {
case errors.As(err, &limitErr) && limitErr.Scope == tenant.GovernanceScopeTenant:
    // HTTP 429; Retry-After may be derived from limitErr.RetryAfter.
case errors.As(err, &limitErr) && limitErr.Scope == tenant.GovernanceScopeGlobal:
    // HTTP 503; shared deployment capacity is temporarily exhausted.
case errors.Is(err, tenant.ErrGovernanceUnavailable):
    // HTTP 503; enforcement could not prove that admission was safe.
}
```

Do not map a governance backend failure to an allowed request. That turns a
Redis outage into an uncontrolled load spike against the database.

## Observability

`telemetry.Provider.TenantGovernorHooks` records:

| Instrument | Meaning | Attributes |
|---|---|---|
| `kayan.governance.decisions` | allowed, limited, and failed admissions | tenant, operation, scope, kind, outcome |
| `kayan.governance.in_flight` | admitted operations not yet released | tenant, operation |
| `kayan.governance.operation.duration` | completed operation duration | tenant, operation |

Tenant labels are needed to identify a noisy neighbor, but they increase metric
cardinality. Large installations should aggregate or drop the tenant label in
the OpenTelemetry Collector and retain per-tenant usage in a billing or audit
store designed for high cardinality.

## What remains infrastructure-owned

Admission control prevents excessive work from entering shared components. It
cannot guarantee CPU time or memory after admission. Production deployments
still need:

- request and query deadlines;
- bounded request bodies and pagination;
- database connection-pool limits and slow-query controls;
- fair per-tenant queues for background jobs;
- container CPU and memory limits; and
- separate workers, pools, schemas, or databases for tenants requiring hard
  performance isolation.

Kayan owns the tenant-aware policy and admission decision. The host owns where
that boundary is called and the infrastructure on the other side.
