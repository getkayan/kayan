# Strategy Internals

This document is for maintainers and advanced integrators who need to understand how Kayan strategies are orchestrated internally.

## Why Strategies Exist

Strategies let the library add new authentication methods without rewriting manager code. The manager is responsible for orchestration. The strategy is responsible for method-specific behavior.

That split is what keeps password, OTP, magic link, WebAuthn, and future methods composable.

## Manager Responsibilities

Managers own:

- thread-safe registration and lookup
- hook execution order
- event dispatch
- audit emission
- optional dynamic configuration reload
- cross-strategy policies such as MFA gating

Strategies should not duplicate that orchestration layer.

## Registration Lifecycle

`RegistrationManager.Submit` roughly does this:

1. load strategy and manager-level configuration under read lock
2. run pre-hooks
3. validate schema if configured
4. attempt optional implicit identity unification
5. call `Register` on the strategy
6. emit failure or success audit and event records
7. run post-hooks

That sequence matters. Hook placement determines whether your application code sees partially created identities or only completed ones.

## Login Lifecycle

`LoginManager.Authenticate` roughly does this:

1. load strategy and hooks under read lock
2. run pre-hooks
3. call `Authenticate`
4. emit login failure or success signals
5. inspect MFA state on the returned identity
6. run post-hooks if the auth step succeeded and is allowed to continue

If MFA is enabled, the login flow returns `ErrMFARequired` so the caller can branch into a second-factor step.

## Dynamic Strategies

`LoginManager` can rebuild strategy instances from `domain.StrategyStore` and a `StrategyRegistry`. This allows runtime control of which methods are active without process restart.

Use this carefully:

- registry build failures should be observable
- configuration source of truth should be versioned or audited
- dynamically disabled strategies must be reflected in the caller UX

## Thread Safety

Managers use `sync.RWMutex` for strategy maps and hook slices. Register strategies at startup when possible. Runtime mutation is supported, but you should still treat configuration changes as operational events that deserve observability.

## Event Topics

The events package gives a shared event vocabulary for auth operations. Use it to bridge core flows into:

- analytics pipelines
- external audit sinks
- webhooks
- fraud and risk engines

This avoids burying side effects inside the strategies themselves.

## Internal Extension Guidance

When implementing a new strategy:

- keep the method-specific logic in the strategy
- keep session issuance outside the strategy
- keep transport parsing outside the strategy
- keep storage requirements narrowed to the minimum required interface
- keep the strategy ID stable once exposed