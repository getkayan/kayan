# Architecture Overview

Kayan is intentionally split into small packages with explicit dependency direction. The architecture is designed to keep core IAM logic reusable across frameworks, storage backends, and schema designs.

## Core Design Principles

### Headless only

Kayan is a library. The core packages do not own routers, templates, handlers, or frontend assets. HTTP middleware exists only where an operation is generic enough to remain transport-neutral, such as standard `net/http` helpers in health or tenant packages.

### Non-generic public APIs

Core extension points use interfaces, `any`, and factories. This keeps the public API compatible with arbitrary model shapes and identifier types.

### BYOS

The library adapts to your schema rather than forcing a canonical `users` table. Reflection and explicit field mapping are used at boundaries, while the core logic remains schema-agnostic.

## Package Layers

### Foundations

- `core/identity`: default types and JSON helpers
- `core/domain`: repository and token contracts
- `core/audit`: audit model and persistence interface
- `core/events`: event envelope and dispatcher abstractions

### Authentication and session layer

- `core/flow`
- `core/session`
- `core/device`
- `core/mfa`
- `core/risk`

### Authorization and tenancy layer

- `core/rbac`
- `core/rebac`
- `core/policy`
- `core/tenant`
- `core/admin`

### Federation and provisioning layer

- `core/oauth2`
- `core/oidc`
- `core/saml`
- `core/scim`

### Operations and compliance layer

- `core/compliance`
- `core/consent`
- `core/config`
- `core/logger`
- `core/telemetry`
- `core/health`

### Adapter layer

- `kgorm`
- `kredis`

Adapters may depend on core packages. Core packages must not depend on adapters.

## Dependency Direction

The repository rules matter here:

- `core/identity` is effectively a leaf dependency and should not import other `core/` packages.
- `core/domain` depends only on `core/identity` and `core/audit`.
- `core/flow` depends on domain, identity, audit, and events.
- `core/session` depends on domain and identity.
- `core/rbac`, `core/rebac`, `core/policy`, and `core/tenant` are intended to stay independently reusable.

This package graph is what prevents framework, storage, and protocol concerns from leaking into the rest of the library.

## Main Architectural Patterns

### Strategy pattern

Authentication methods, MFA methods, authorization engines, and tenant resolvers all use pluggable strategies or methods.

### Manager pattern

Managers own registration, orchestration, hooks, and concurrency safety. They do not hardcode one auth method or one storage backend.

### Consumer-defined interfaces

Interfaces live where behavior is consumed. Storage contracts are declared in `core/domain`. Policy contracts are declared in `core/policy`. This keeps public dependencies narrow.

### Hook-based extensibility

Kayan favors hooks over inheritance. That keeps call paths explicit and composable in Go.

## What Belongs Where

Put logic in `core/` when it is:

- headless
- broadly reusable
- framework-agnostic
- expressible via stable interfaces

Put logic in an adapter when it is:

- database-specific
- cache-specific
- HTTP framework-specific
- tied to external SDKs or deployment assumptions

## Reading the Codebase

When navigating the repository, use this path:

1. `core/domain` to understand persistence contracts
2. `core/flow` and `core/session` to understand authentication lifecycle
3. `core/rbac`, `core/policy`, and `core/rebac` for authorization choices
4. `core/oauth2`, `core/oidc`, `core/saml`, `core/scim` for protocol integrations
5. `kgorm` and `kredis` for concrete infrastructure patterns

The rest of the architecture docs expand each of those layers in detail.