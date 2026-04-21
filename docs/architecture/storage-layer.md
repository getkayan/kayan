# Storage Layer

Kayan's storage model is intentionally interface-first. `core/domain` defines what persistence must do. Adapters such as `kgorm` and `kredis` decide how it is done.

## Core Interfaces

The central contract is `domain.Storage`, which composes:

- `IdentityStorage`
- `SessionStorage`
- `CredentialStorage`
- `audit.AuditStore`
- `TokenStore`

Not every feature needs the full composite interface. Use the narrowest contract your package actually requires.

## BYOS Implications

Storage methods commonly accept factories and `any` so they can materialize your identity type without importing it into `core/` packages.

Example responsibilities:

- `CreateIdentity(ident any)` persists a BYOS identity
- `GetIdentity(factory, id)` materializes the target type
- `FindIdentity(factory, query)` resolves by mapped identifiers or custom fields

## Adapter Responsibilities

Adapters should own:

- SQL or Redis schema decisions
- marshaling between rows and domain structs
- transactions
- index choices
- cache key layout
- migration code where applicable

Core packages should never import an adapter to get those behaviors.

## GORM Adapter

`kgorm` is the reference storage implementation for relational databases. It covers:

- identities and credentials
- sessions
- audit events
- OAuth 2.0 stores
- RBAC and ReBAC repositories
- SCIM persistence helpers

Use it when you want a full relational backend with minimal glue code.

## Redis Adapter

`kredis` is not a replacement for your system of record. It provides shared infrastructure for short-lived and distributed state:

- session support
- rate limiting
- account lockout
- WebAuthn or challenge-adjacent storage

Use it alongside a primary repository, not instead of one.

## Store Design Guidance

- Keep identity and credential writes transactional when they must succeed together.
- Back lockout and rate limiting with shared storage in multi-instance deployments.
- Treat token stores as security-sensitive persistence, not as best-effort caches.
- Separate long-lived identity records from short-lived ephemeral auth artifacts.

## Testing Stores

The repository already demonstrates the expected testing style:

- unit tests close to each store implementation
- repository integration coverage in `kgorm/repository_test.go`
- race-safe manager behavior in the consuming packages

If you write a new adapter, mirror the `kgorm` and `kredis` testing depth before treating it as production-ready.