# Extending Kayan

The safest way to extend Kayan is to reuse its existing patterns: strategies, managers, store interfaces, and hooks. Do not bypass those patterns unless you are intentionally building a new subsystem.

## Add a New Authentication Method

Implement `RegistrationStrategy`, `LoginStrategy`, or both depending on whether the method supports sign-up, sign-in, or both.

Checklist:

1. choose a stable lowercase strategy ID
2. define the minimal storage interface the method needs
3. keep transport and framework code outside `core/`
4. add table-driven tests
5. register the strategy through existing managers

If the method is multi-step, also implement `Initiator`. If it can attach credentials to an existing account, implement `Attacher`.

## Add a New MFA Method

Implement `mfa.Method` and register it with `mfa.Manager`. The manager already handles:

- enrollment lifecycle
- challenge persistence
- challenge expiry
- one-time challenge consumption

Your method should focus on enrollment data, challenge generation, and verification logic.

## Add a New Authorization Engine

Implement `policy.Engine` if the new model fits the `Can(ctx, subject, action, resource)` contract. If the model is graph-based, consider whether it belongs as a ReBAC extension instead.

Keep new authorization packages standalone unless they truly need dependencies on the existing auth or storage layers.

## Add a New Tenant Resolver

Implement `tenant.Resolver` and keep it transport-agnostic where possible. If the resolver is HTTP-specific, keep the HTTP extraction as thin as possible and convert into `tenant.ResolveInfo` early.

## Add a New Storage Adapter

Put new database or cache integrations outside `core/`. Follow the adapter model used by `kgorm` and `kredis`.

Adapter rules:

- depend on `core/domain` and the package-specific contracts you need
- never require `core/` packages to import the adapter
- preserve BYOS by accepting user-provided models or factories

## Add a New Core Package

Only add a new `core/` package when:

- the responsibility is clearly bounded
- the package graph remains valid
- the feature is headless and reusable
- tests and docs are added together

If a feature is tied to one framework or one persistence technology, it does not belong in `core/`.

## Documentation and Verification

Every meaningful extension should update:

- package doc comments
- architecture docs where the package fits in the graph
- the feature-specific docs for developers
- unit and race-safe tests

Use the existing tests as templates. The repository already demonstrates the expected style for strategies, managers, and adapters.