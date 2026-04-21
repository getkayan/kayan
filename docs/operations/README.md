# Operations

This section covers deployment and runtime guidance for operating Kayan-powered systems in development and production.

## Deployment Model

Kayan is embedded into your service or services. The operational surface therefore depends on how you compose it:

- monolith or API service embedding `core/flow` and `core/session`
- dedicated auth service exposing OAuth 2.0, OIDC, SAML, or SCIM endpoints
- internal admin service wrapping `core/admin`
- background workers for retention, audit export, or provisioning jobs

## State Placement

Use durable storage for:

- identities
- credentials
- sessions if using the database strategy
- audit events
- refresh tokens
- tenant metadata

Use shared ephemeral storage for:

- rate limits
- lockout state
- revocation entries
- short-lived login artifacts
- challenge state where protocol flow spans multiple requests

## Health and Readiness

Expose `core/health` endpoints for:

- liveness
- readiness
- full diagnostic health reports

Register checks for every dependency that can break authentication correctness, not just for the primary database.

## Observability

Use all three layers together:

- structured logs for debugging and incident response
- telemetry for metrics and traces
- audit events for regulated, user-impacting state changes

Do not treat audit as a substitute for telemetry, or telemetry as a substitute for audit. They answer different operational questions.

## Key and Secret Management

- keep session, OAuth 2.0, OIDC, and SAML keys outside source control
- rotate signing keys deliberately and test verification paths during rotation
- protect client secrets and MFA seeds as secrets, not configuration literals

## Multi-Instance Guidance

If you run more than one instance, assume memory-only security state is insufficient. Back the following with shared storage:

- rate limiting
- lockout
- JWT revocation
- protocol pending-session state

## Retention and Cleanup

Use `core/compliance` retention helpers or equivalent jobs to clean:

- expired sessions
- old refresh tokens
- obsolete challenge and recovery artifacts
- audit data according to policy
- consent records according to legal retention requirements

## Admin and Back-Office Surfaces

Wrap `core/admin` in a separately secured transport boundary. Admin capabilities are high impact and should have stronger authorization, audit logging, and, where appropriate, step-up authentication.

## Recommended Production Checklist

- tenant resolution is explicit and tested
- password policy is enabled
- rate limiting and lockout are enabled
- session strategy matches revocation requirements
- audit store is configured
- telemetry and health checks are wired
- secrets and signing keys are externally managed
- distributed state uses shared backends