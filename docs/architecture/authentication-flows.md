# Authentication Flows

This section explains how registration, login, recovery, verification, MFA, device trust, and step-up authentication fit together inside Kayan.

## Flow Pipeline

The typical authentication path is:

1. Resolve tenant context if the deployment is multi-tenant.
2. Choose the flow manager and strategy by method ID.
3. Run pre-hooks.
4. Perform schema validation or initiation if applicable.
5. Delegate to the strategy.
6. Emit audit and event records.
7. Run post-hooks.
8. Issue or refresh a session.

This separation is deliberate. A flow authenticates the identity. Session issuance is a separate concern handled by `core/session`.

## Registration

`RegistrationManager.Submit` accepts:

- a method ID
- a traits payload
- a secret or method-specific credential value

Registration supports:

- strategy dispatch
- schema validation through `identity.Schema`
- implicit account unification through a `Linker`
- opt-in prevention of password capture on existing identities
- audit and event emission

Important behavior:

- if an existing identity is found and the configured linker can attach the new method, registration can return the existing identity instead of creating a duplicate
- password registration can be configured to fail instead of attaching to an existing user with `WithPreventPasswordCapture`

## Login

`LoginManager.Authenticate` performs pre-hooks, delegates to the selected strategy, emits login success or failure signals, and checks whether MFA is required.

If the authenticated identity implements `flow.MFAIdentity` and MFA is enabled, the login manager returns `flow.ErrMFARequired`. That allows your handler to branch into a second-factor challenge instead of incorrectly treating primary-factor success as a fully authenticated session.

## Multi-Step Methods

Some login methods require initiation before completion.

Examples:

- magic link email dispatch
- OTP generation and out-of-band delivery
- protocol-specific external redirect workflows

Those methods should implement `Initiator`, allowing `LoginManager.InitiateLogin` to create the first-step artifact while preserving the same audit and event model.

## Recovery and Verification

`core/flow` includes recovery and verification helpers backed by token stores. These flows are designed for capabilities such as:

- email verification after registration
- password reset via recovery token
- method-specific account recovery workflows

Persist these tokens in a store appropriate for expiry and revocation semantics. Redis-backed stores are a good fit for short-lived tokens in distributed environments.

## Password Policies

Password security is not left to the UI. `core/flow/password_policy.go` enforces server-side rules such as:

- minimum length
- character-class requirements
- entropy-oriented complexity checks

Apply the policy directly on the password strategy or through `flow.PasswordAuth` options.

## Rate Limiting and Lockout

Rate limiting and lockout are explicit parts of the auth architecture, not optional afterthoughts.

Rate limiting limits request frequency by identifier, credential, IP, or a composite key, depending on your wrapper strategy.

Lockout tracks failed attempts across a time window and can temporarily deny further authentication attempts. In distributed systems, use Redis-backed stores from `kredis` so failures are visible across instances.

## MFA and Step-Up

There are two MFA-related layers in the repository:

- `core/flow` contains login-time MFA checks and TOTP-related flow behavior
- `core/mfa` is a standalone enrollment and challenge orchestration package for broader multi-factor lifecycle management

Use `core/mfa` when you need:

- enrollment state management
- per-method challenge objects
- backup codes
- multiple concurrently registered MFA methods

Use `core/flow` when you need authentication manager integration that blocks session issuance until second factor completion.

Step-up authentication in `core/flow/stepup.go` is intended for sensitive actions after the primary session already exists, for example changing a password, exporting data, or granting privileges.

## Device Trust and Risk

`core/device` and `core/risk` are adjacent services that should influence your authentication decisions:

- unknown or low-trust devices can trigger MFA or step-up
- impossible-travel and geo-change risk signals can increase the required assurance level
- remembered or high-trust devices can reduce friction without bypassing policy

The recommended pattern is to evaluate device trust and risk in pre-hooks or immediately after primary-factor success, then branch into the required next step.

## Event and Audit Boundaries

Every meaningful state transition in a flow should be observable:

- registration success or failure
- login initiation
- login success or failure
- MFA requirement and completion
- recovery token generation and redemption

Kayan already emits core audit and event signals when the relevant store or dispatcher is configured. Use those as the source of truth for downstream analytics and compliance systems.