# Storage Adapters

Kayan keeps adapters outside `core/` so databases and caches can evolve without dragging transport or persistence assumptions into the IAM logic.

## kgorm

`kgorm` is the primary relational adapter in the repository.

It provides repository implementations for:

- identities and credentials
- sessions
- audit events
- OAuth 2.0 clients, auth codes, and refresh tokens
- RBAC persistence helpers
- ReBAC tuples and schema-adjacent storage
- SCIM persistence helpers

### When to use it

Use `kgorm` when your system of record is a relational database and you want the fastest path to production.

### What it demonstrates

Even if you do not use GORM, `kgorm` is the reference example of how to implement `core/domain` and related package interfaces while respecting BYOS.

## kredis

`kredis` is the shared-state adapter for distributed auth concerns.

It provides:

- session support for Redis-backed flows
- rate limiting
- account lockout storage
- WebAuthn-related persistence helpers

### When to use it

Use `kredis` when you deploy multiple application instances and need shared security state across them.

Typical examples:

- rate limit counts visible to all instances
- lockout windows shared across all login workers
- short-lived auth artifacts with TTL-based expiry

## Recommended Combined Architecture

The common production topology is:

- `kgorm` as the durable system of record
- `kredis` for distributed volatile state

That combination gives you strong persistence plus low-latency shared counters and expirations.

## Writing a New Adapter

Follow the same rules as the built-in adapters:

- depend on the relevant `core/` contracts only
- keep persistence concerns out of `core/`
- preserve BYOS by honoring factories and `any`
- write package-local tests plus integration coverage

If your adapter needs its own schema, migration tooling, or client connection management, keep that code in the adapter package rather than in consuming applications.