---
name: new-auth-strategy
description: 'Implement a new authentication strategy (registration and/or login) for Kayan. Use when adding a new auth method such as magic link, WebAuthn, TOTP, passkey, social login, or any custom scheme.'
argument-hint: 'Name and description of the auth strategy to implement (e.g., "magic link via email", "TOTP-based login")'
user-invocable: true
---

# New Auth Strategy

Implement a new Kayan authentication strategy that integrates with the existing `RegistrationManager` and `LoginManager`.

## When to Use

- Adding a new auth method: magic link, WebAuthn, TOTP, passkey, OAuth2 social login, SMS OTP, etc.
- Replacing or extending an existing strategy
- Creating a custom auth scheme for a specific use case

## What This Skill Produces

- A `strategy_<name>.go` file implementing `RegistrationStrategy` and/or `LoginStrategy`
- A `strategy_<name>_test.go` file with table-driven tests
- Registration of the strategy with the manager via `RegisterStrategy`
- Any required sentinel errors in `errors.go` or the strategy file

## Required Inputs

- Strategy name (lowercase, underscored, e.g. `magic_link`)
- Which interfaces to implement: `RegistrationStrategy`, `LoginStrategy`, or both
- Whether the flow is multi-step (requires `Initiator` interface)
- Dependencies: storage interfaces needed, external packages

## Key Files to Read First

Before implementing, read these files for patterns and conventions:

| File | What to learn |
|------|--------------|
| `core/flow/strategy_password.go` | Canonical strategy implementation, BYOS field mapping |
| `core/flow/login.go` | `LoginManager` — how strategies are registered and invoked |
| `core/flow/flow.go` | `RegistrationStrategy`, `LoginStrategy`, `Initiator` interfaces |
| `core/flow/errors.go` | Existing sentinel errors; add new ones here |
| `core/flow/lockout.go` | Lockout integration pattern |
| `core/flow/magic_test.go` | Example test for a multi-step strategy |
| `core/domain/storage.go` | Storage interfaces the strategy can depend on |
| `docs/architecture/strategy-internals.md` | Full strategy pattern documentation |

## Procedure

### 1. Name the strategy

- ID string must be lowercase, alphanumeric with underscores: `"password"`, `"magic_link"`, `"webauthn"`
- File name: `strategy_<name>.go` and `strategy_<name>_test.go`

### 2. Define the struct

```go
// strategy_<name>.go
package flow

type <Name>Strategy struct {
    repo    <Name>Repository  // consumer-defined interface — define it below
    factory func() any        // BYOS: returns the user's model instance
    // ... strategy-specific fields
}

func New<Name>Strategy(repo <Name>Repository, factory func() any) *<Name>Strategy {
    return &<Name>Strategy{repo: repo, factory: factory}
}

func (s *<Name>Strategy) ID() string { return "<name>" }
```

### 3. Define the storage interface (consumer-defined)

Define the interface **in this file** (consuming package), not in the adapter:

```go
// <Name>Repository is the storage contract for the <name> strategy.
type <Name>Repository interface {
    // Add only what this strategy needs — keep it minimal
    FindIdentityBy<Field>(ctx context.Context, value string, factory func() any) (any, error)
}
```

### 4. Implement the interfaces

**Single-step flow** (e.g., password):
```go
func (s *<Name>Strategy) Register(ctx context.Context, traits identity.JSON, secret string) (any, error) { ... }
func (s *<Name>Strategy) Authenticate(ctx context.Context, identifier, secret string) (any, error) { ... }
```

**Multi-step flow** (e.g., magic link — initiate then verify):
```go
// Implements Initiator (optional interface for two-step flows)
func (s *<Name>Strategy) Initiate(ctx context.Context, identifier string) (any, error) { ... }
// Authenticate is the verification step
func (s *<Name>Strategy) Authenticate(ctx context.Context, identifier, token string) (any, error) { ... }
```

### 5. BYOS field mapping

If the strategy reads/writes user model fields, follow the `PasswordStrategy` pattern:

```go
// MapFields connects this strategy to user-defined struct field names
func (s *<Name>Strategy) MapFields(identifiers []string, tokenField string) {
    s.identifierFields = identifiers  // e.g., []string{"Email"}
    s.tokenField = tokenField          // e.g., "MagicToken"
}
```

Use `reflect` or `identity.MapFields` to set/get fields — never hardcode field names.

### 6. Error handling

Add sentinel errors to `core/flow/errors.go` if consumers need to branch on them:

```go
var Err<Name>TokenExpired = errors.New("<name>: token expired")
var Err<Name>TokenInvalid = errors.New("<name>: token invalid")
```

Use `fmt.Errorf("flow: <name>: description: %w", err)` for wrapped errors.

### 7. Security checklist

- [ ] Token comparison uses `subtle.ConstantTimeCompare` — never plain `==`
- [ ] Tokens are cryptographically random (`crypto/rand`), not `math/rand`
- [ ] Tokens have expiry enforced server-side
- [ ] Secrets/tokens are never logged
- [ ] If handling passwords: use `domain.Hasher` (bcrypt), not raw hashing

### 8. Write table-driven tests

```go
// strategy_<name>_test.go
package flow_test

func TestNew<Name>Strategy_Register(t *testing.T) {
    tests := []struct {
        name    string
        traits  identity.JSON
        secret  string
        wantErr bool
    }{
        {name: "valid registration", ...},
        {name: "missing required field", ..., wantErr: true},
    }
    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) { ... })
    }
}
```

- Use a **mock/stub** storage — never a real DB in unit tests
- Run with `go test -race ./...` to check for data races

### 9. Register with the manager

Show users how to register the strategy in their setup code (in docs or example):

```go
strategy := flow.New<Name>Strategy(repo, func() any { return &User{} })
strategy.MapFields([]string{"Email"}, "<TokenField>")
loginManager.RegisterStrategy(strategy)
```

## Constraints

- **No generics** — use `any` + type assertions, not `[T any]`
- **No framework imports** in `core/` — keep the strategy framework-agnostic
- **No direct DB imports** — depend on the storage interface you defined
- **Audit integration** — check `if m.auditStore != nil` before logging (never panic)
- **Thread safety** — strategies must be safe for concurrent use; avoid mutable shared state

## Completion Checklist

- [ ] `strategy_<name>.go` implements `ID() string` and the required interfaces
- [ ] Storage interface is defined in the consuming package (`core/flow/`)
- [ ] BYOS field mapping implemented if reading/writing user model fields
- [ ] Sentinel errors added to `errors.go` for consumer-handleable cases
- [ ] `strategy_<name>_test.go` with table-driven tests passes `go test -race ./...`
- [ ] `docs/architecture/strategy-internals.md` or `docs/concepts/strategies.md` updated if behavior is novel
