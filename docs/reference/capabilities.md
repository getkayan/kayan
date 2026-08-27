# Capability and Stability Matrix

Kayan is pre-1.0. This page is the source of truth for what the project supports
today and what must be proven before an API is declared stable.

Kayan is a headless library. It requires no database, ORM, cache, HTTP framework,
UI, or server runtime. `kayan-gorm` and `kayan-redis` are optional reference
adapters; applications may implement the consumer-defined interfaces instead.

Package-level freeze status and remaining evidence gates are tracked in the
[API stability map](api-stability.md).

## Current capabilities

| Area | Status | Notes |
|---|---|---|
| Identity contracts and BYOS | Release candidate | Arbitrary models and ID types through `FlowIdentity`, `any`, and factories |
| Password, OTP, TOTP, magic link, API key, recovery | Release candidate | Transient credentials have an atomic single-use storage contract; external review remains required |
| WebAuthn and social/OIDC login | Experimental | Security-sensitive multi-step flows are still being hardened |
| JWT and database sessions | Release candidate | SSO has transport-neutral contracts plus optional GORM and Redis adapters; multi-node operation remains experimental |
| RBAC, ABAC, hybrid policy | Release candidate | ReBAC object enumeration remains incomplete |
| OAuth 2.0 and OIDC provider | Experimental | Authorization code uses PKCE; protocol audit persistence has an explicit failure callback; formal certification remains pending |
| SAML 2.0 | Experimental | Metadata retrieval is injectable, bounded, and public-HTTPS-only by default; interoperability evidence remains pending |
| SCIM 2.0 | Experimental | Discovery, value-path parsing, and filtered PATCH sub-attributes are implemented; storage adapters may explicitly reject multi-valued shapes they cannot represent |
| GORM and Redis adapters | Experimental, optional | GORM passes the shared storage suite; CI exercises concurrent atomicity on real PostgreSQL/MySQL and SSO lifecycle/concurrency on real Redis |
| CLI | Experimental | Its remote administration API is not part of the stable library contract |

## Deferred beyond 1.0

The first stable release does not include OAuth device authorization, token
exchange, DPoP, `private_key_jwt`, dynamic client registration, or SCIM bulk.
Unsupported capabilities must not be advertised by discovery metadata.

## The 1.0 gate

A capability becomes stable only after its public contract is frozen, unit and
race tests pass, relevant integration and conformance suites pass, documentation
examples compile, and critical or high findings from the independent security
review are resolved. Compliance helpers are not claims of SOC 2, ISO 27001,
GDPR, or CCPA certification.
