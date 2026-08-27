# API stability map

This map classifies the proposed 1.0 public surface. All listed modules are
machine-checked for source compatibility, including experimental packages;
changing an experimental API still requires an explicit baseline update and
release-note decision rather than bypassing review.

## Release-candidate contracts

These packages define Kayan's headless integration seams and are intended to
become stable in 1.0:

- `core/identity`, `core/domain`, `core/audit`, and `core/events`
- `core/flow`, `core/session`, `core/keys`, and `core/tenant`
- `core/rbac`, `core/rebac`, and `core/policy`
- `core/mfa`, `core/device`, and `core/risk`
- `kayan-testing`, as the adapter conformance contract

The freeze covers exported Go source compatibility. Security fixes may still
tighten validation or reject inputs that were previously accepted insecurely.

## Frozen but experimental

These surfaces are protected from accidental API breaks, but are not declared
stable until their evidence gates pass:

| Surface | Remaining gate |
|---|---|
| `kayan-gorm` | Real-database CI and migration rollback history across release candidates |
| `kayan-redis` | Real Redis CI and multi-node operational evidence |
| `kayan-oidc-provider/*` | Independent security review and OpenID conformance evidence |
| `kayan-saml` | Independent security review and published multi-vendor interoperability evidence |
| `kayan-scim` and `kayan-scim/gormstore` | Multi-valued storage mapping policy and SCIM interoperability evidence |
| `kayan-ldap` | TLS/bind interoperability evidence against supported directories |
| `core/admin`, `core/compliance`, `core/config`, `core/consent` | Behavioral-contract review and production adoption evidence |
| `core/health`, `core/logger`, `core/telemetry` | Backend interoperability and operational-contract review |

Experimental packages may change before 1.0, but each change must be deliberate:
update the API baseline, changelog, migration notes, capability matrix, and
affected examples in the same review.

## Outside the Go API snapshot

The root CLI is a command rather than an importable library. Its documented
command/flag surface has a checksum compatibility test; individual response
formats still require command-level contract tests. Database migrations,
serialized tokens, protocol wire behavior, and documentation examples likewise
need their own compatibility tests; `apidiff` cannot validate them.
