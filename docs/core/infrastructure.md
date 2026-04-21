# Infrastructure Packages

This document covers the packages that support the rest of the library: audit, events, config, consent, compliance, logging, telemetry, health, device trust, risk, MFA orchestration, and admin operations.

## Audit

`core/audit` provides the audit event schema and persistence interface.

Use it to record:

- authentication successes and failures
- registration and recovery flows
- consent grants and revocations
- admin mutations
- role, session, and tenant changes

Important fields include actor, subject, tenant, status, message, metadata, device, geo, and risk. If your repository implements `audit.AuditStore`, several flow and protocol packages emit audit events automatically.

## Events

`core/events` is the lightweight event bus for the library. It is intentionally smaller than a full message broker abstraction.

Use it when you need to decouple core behavior from side effects such as:

- webhooks
- analytics
- fraud pipelines
- cache invalidation
- notification triggers

The default dispatcher supports sync or async fan-out and predefined event topics for auth, identity, RBAC, security, and admin actions.

## Config

`core/config` loads environment-based configuration with Viper. Its current default surface includes:

- `DB_TYPE`
- `DSN`
- `SKIP_AUTO_MIGRATE`
- `LOG_LEVEL`
- `OIDC_PROVIDERS`

Treat this package as a starting point for host application config, not as the only valid configuration model for Kayan deployments.

## Consent

`core/consent` tracks user consent decisions with versioning, timestamps, optional expiration, and audit-friendly history.

Use it when you need:

- GDPR or CCPA evidence
- revocable marketing or analytics consent
- essential-purpose protection
- export of stored consent history

The manager API is built around a store plus a policy version string. Keep that version aligned with your actual privacy notice or product policy revision.

## Compliance

`core/compliance` adds operational helpers for retention and sensitive data protection.

Capabilities include:

- retention policies for audit, sessions, consent, and other records
- periodic cleanup management
- AES-256-GCM field encryption helpers
- security headers middleware for browser-facing integrations

This package is intentionally supportive rather than all-encompassing. It gives reusable building blocks; your application remains responsible for actual regulatory policy and legal interpretation.

## Logger

`core/logger` standardizes structured logging around zap. Use it as the base logger for Kayan-adjacent services when you want consistent fields and log levels.

Operational guidance:

- attach request IDs and tenant IDs early
- avoid logging secrets, raw tokens, or unhashed credentials
- align log format with your telemetry and audit correlation strategy

## Telemetry

`core/telemetry` adds OpenTelemetry traces and Prometheus-compatible metrics.

Predefined metric families cover:

- logins
- registrations
- MFA attempts
- rate-limit events
- lockout events
- auth latency
- active session counts

Use OTLP export for tracing and a Prometheus scrape path for metrics. Telemetry can be disabled safely for tests or minimal deployments.

## Health

`core/health` gives you:

- liveness status
- readiness status
- full health report with per-check latency
- built-in database and Redis checkers
- custom checker registration

This package is intentionally `net/http` friendly so it can be mounted in any service without adding framework dependencies.

## Device Trust

`core/device` manages device registration, fingerprinting, last-seen tracking, trust levels, and maximum-device policies. It is useful when your auth posture depends on whether the login originates from a known device.

Combine it with MFA and risk scoring for adaptive assurance.

## MFA Orchestration

`core/mfa` is broader than the MFA checks in `core/flow`. It manages:

- method registration
- enrollment states
- challenge creation and expiry
- verification
- recovery code generation and verification

Use it when MFA is a first-class product feature, not just a login-time toggle.

## Risk

`core/risk` evaluates signals into a structured assessment. Rules can score failed attempts, device novelty, geo anomalies, and custom inputs. The output is intended to feed policy decisions such as challenge, deny, or allow.

## Admin

`core/admin` is the framework-agnostic back-office management API. It provides CRUD-style operations and query surfaces for:

- users
- sessions
- roles
- tenants
- audit events

The package does not ship an HTTP API. Instead, wrap the manager in your own admin transport while keeping authorization and tenant scoping explicit.