# Multi-Tenancy

`core/tenant` provides transport-agnostic tenant resolution and validation. It is designed to sit in front of authentication, authorization, provisioning, and admin operations without forcing a specific routing model.

## Manager Responsibilities

`tenant.NewManager(store, resolver, opts...)` handles:

- resolving a tenant ID from request metadata
- validating existence and active state
- adding tenant information to context
- running lifecycle hooks
- creating a scoped store wrapper when needed

## Built-in Resolvers

Use a resolver that matches your tenancy model:

- subdomain-based: `acme.example.com`
- header-based: `X-Tenant-ID: acme`
- path-based: `/t/acme/...`

The manager also exposes `ResolveFromRequest` and HTTP middleware helpers for standard `net/http` stacks.

## Default and Optional Tenants

Use `tenant.WithOptionalTenant()` when some routes are tenantless. Use `tenant.WithDefaultTenant(id)` when a fallback tenant exists and tenant selection should not fail hard.

Keep required and optional flows explicit. Public auth flows with optional tenants can become ambiguous if email addresses or usernames are not globally unique.

## Full Tenant vs Lightweight Mode

By default, the manager loads the full tenant object and places it in context. Use `tenant.WithLightweight()` when you only need tenant ID and want to avoid the extra object load in hot paths.

## Hooks

Hooks are available for:

- pre-resolution overrides
- post-resolution side effects
- tenant validation
- failure handling
- tenant creation workflows

Typical uses:

- enforcing plan status or feature flags
- attaching tenant-specific telemetry attributes
- implementing custom domain allowlists

## Scoped Storage

`tenant.NewScopedStore(inner, tenantID)` wraps a store so your application code can enforce tenant scoping consistently. This is especially useful when your repository layer expects tenant identity as part of every query.

## Interaction with Other Packages

- `core/flow`: use resolved tenant context before registration or login if identity uniqueness is tenant-scoped
- `core/policy` and `core/rbac`: pass tenant context into rules or permission loaders
- `core/admin`: scope list and mutation operations for non-super-admin callers
- `core/audit`: include tenant IDs in audit event metadata and actor context

## Operational Guidance

- Resolve tenants early in the request lifecycle.
- Decide whether identities are globally unique or tenant-local and keep that invariant consistent.
- Test inactive and unknown tenant cases as first-class security scenarios.
- Avoid implicit fallback tenants in production unless the business model truly requires them.