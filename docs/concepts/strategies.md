# Authentication Strategies

`core/flow` is built around strategies and managers.

- A strategy implements the authentication method.
- A manager owns strategy registration, hooks, event emission, and orchestration.
- Your application wires managers into handlers, RPC methods, jobs, or CLIs.

## Core Interfaces

```go
type RegistrationStrategy interface {
	ID() string
	Register(ctx context.Context, traits identity.JSON, secret string) (any, error)
}

type LoginStrategy interface {
	ID() string
	Authenticate(ctx context.Context, identifier, secret string) (any, error)
}
```

Additional strategy capabilities are exposed by optional interfaces:

- `Initiator`: first step of multi-stage methods such as magic link or OTP
- `Attacher`: links new credentials to an existing identity during account unification

## Managers

### Registration manager

`flow.NewRegistrationManager` handles:

- strategy dispatch by method ID
- pre and post hooks
- schema validation
- optional account linking and implicit unification
- audit event emission
- event dispatch through `core/events`

### Login manager

`flow.NewLoginManager` handles:

- strategy dispatch by method ID
- optional initiation for multi-step methods
- pre and post hooks
- automatic audit and event emission
- MFA-required signaling via `flow.ErrMFARequired`
- dynamic strategy reloads through `domain.StrategyStore`

Managers are thread-safe and use `sync.RWMutex` internally for registration and lookup.

## Built-in Strategy Patterns

### Password

Use when you control credential storage and want standard email or username plus secret authentication.

Key features:

- bcrypt hashing
- identifier field mapping
- password policy enforcement
- ID generation for new identities
- compatibility with BYOS models

### Magic link

Use for passwordless email workflows. These strategies typically support `Initiate` for request creation and then `Authenticate` for the completion step.

### OTP and TOTP

Use for one-time codes or step-up verification. OTP strategies fit transport-delivered codes. TOTP is suited to app-based authenticators.

### WebAuthn

Use when you want phishing-resistant passkeys or hardware-backed login factors. Kayan keeps the strategy pluggable so the credential and ceremony state can be backed by your storage layer.

### OIDC and SAML-linked login

Federated methods can be represented as strategies or composed at the handler layer using the protocol packages. Keep protocol handling separate from core flow orchestration where possible.

## Hooks

Hooks are the main extension mechanism when you need application-specific behavior without forking strategy code.

Registration hooks:

- validate traits before persistence
- enrich tenant or audit context
- reject registration based on business rules
- trigger async welcome or verification workflows

Login hooks:

- perform pre-auth risk checks
- attach device metadata
- update last-login fields
- emit domain events into your own event bus

## Dynamic Strategy Configuration

`LoginManager` can reload strategies from `domain.StrategyStore` and a `StrategyRegistry`. This is useful when enabled methods are controlled by admin configuration or tenant-level rollout data.

Use that path when:

- strategies can be enabled or disabled at runtime
- tenant plans control which methods are active
- you need a database-backed registry of auth methods

Use static registration when the method set is fixed at process start.

## Strategy ID Rules

Strategy IDs are part of the public contract. Keep them:

- lowercase
- alphanumeric with underscores
- stable once published

Examples: `password`, `magic_link`, `otp`, `webauthn`

## Recommended Composition

- Start with `flow.PasswordAuth` if you only need password auth.
- Switch to explicit managers when you need multi-method auth, hooks, or custom linking.
- Wrap strategies with rate limiting and lockout before exposing them to the network.
- Keep transport concerns outside the strategy implementation.