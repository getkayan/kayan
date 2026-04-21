# Session Management

`core/session` separates authentication from session issuance. A flow authenticates an identity. A session strategy decides how that authenticated identity becomes a reusable login state.

## Session Strategy Interface

```go
type Strategy interface {
	Create(sessionID, identityID any) (*identity.Session, error)
	Validate(sessionID any) (*identity.Session, error)
	Refresh(refreshToken string) (*identity.Session, error)
	Delete(sessionID any) error
}
```

The built-in manager wraps this interface and provides a stable application-facing API.

## Database Strategy

`session.NewDatabaseStrategy(repo)` is stateful and revocable.

Characteristics:

- persists sessions through `domain.SessionStorage`
- generates refresh tokens automatically
- rotates both session ID and refresh token on refresh
- invalidates the old session after successful rotation
- is the best default when you need admin-driven session termination

Use it when you need:

- hard revocation guarantees
- session analytics
- per-session metadata and auditability
- easy admin visibility into active sessions

## JWT Strategy

`session.NewJWTStrategy` and `session.NewHS256Strategy` support stateless access tokens plus refresh tokens.

Characteristics:

- configurable signing and verification keys
- configurable access and refresh expiries
- optional refresh-token validation hook
- optional revocation store for distributed invalidation

Use it when you need:

- horizontally scalable validation without database reads on every request
- interoperability with standard JWT tooling
- short-lived access tokens backed by a revocation channel

## Revocation Stores

JWT sessions are only truly operationally safe in multi-instance deployments when revocation is backed by shared storage. The built-in memory store is suitable for tests and local development. Use Redis or another distributed backend in production.

Recommended pattern:

- short access-token TTL
- refresh-token rotation
- Redis-backed revocation for logout and emergency invalidation

## Session Shape

The default session model contains:

- session ID
- identity ID
- access token or session identifier
- refresh token
- issued, access expiry, and refresh expiry timestamps
- active flag

Identity ID is distinct from session ID. Preserve that distinction in your own stores and handlers.

## Refresh Semantics

Kayan intentionally treats refresh as a security-sensitive state transition.

For database sessions, refresh issues a new session identity and invalidates the old one. For JWT sessions, refresh issues new signed tokens and can be augmented with custom token validation.

Design your clients to replace both access and refresh tokens atomically.

## Recommended Deployment Modes

### Monolith or single instance

- database sessions are simplest
- memory revocation is acceptable for local-only JWT experiments

### Distributed API fleet

- JWT access tokens for read-heavy request validation
- Redis-backed revocation and refresh-token persistence
- centralized audit and telemetry

### Strict admin-control environments

- database sessions with admin listing and forced termination
- strong audit correlation on issue, refresh, and revoke operations

## Related Features

- `core/flow/stepup.go` supports elevated authentication requirements around sensitive actions.
- `core/device` and `core/risk` can influence whether a session should be issued or challenged.
- `core/admin` exposes session querying and revocation patterns for back-office tools.