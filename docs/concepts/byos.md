# BYOS: Bring Your Own Schema

Kayan is designed around the assumption that your identity model already exists, or will be designed around your product needs rather than around a library's required struct shape. BYOS is implemented through a narrow minimum interface plus reflection-based field mapping at the edges.

## Minimum Contract

Authentication flows require only:

```go
type FlowIdentity interface {
	GetID() any
	SetID(any)
}
```

That is the only mandatory identity contract in `core/flow`. Your ID can be a UUID, ULID, integer, string, composite wrapper, or application-specific type.

## Optional Capability Interfaces

Kayan enables additional behavior through narrow optional interfaces instead of forcing a large base model:

- `flow.TraitSource`: exposes flexible `identity.JSON` traits
- `flow.CredentialSource`: exposes discrete credentials when you manage credential records on the model
- `flow.MFAIdentity`: tells the login manager whether MFA is enabled and which secret to use
- `flow.VerificationIdentity`: supports verification and recovery workflows
- `rbac.RoleSource` and `rbac.PermissionSource`: supply roles and permissions

The design goal is additive capability. You opt into only the surfaces you need.

## Traits and Field Mapping

Password and recovery flows often need to extract fields such as `email`, `phone`, `username`, or `password_hash` from custom models. Kayan handles this by mapping fields instead of requiring fixed names.

Typical pattern:

```go
strategy := flow.NewPasswordStrategy(repo, hasher, "email", factory)
strategy.MapFields([]string{"Email", "PrimaryEmail"}, "PasswordHash")
```

This lets you point Kayan at your model's actual fields while preserving your schema. The library uses these mappings at boundaries, not throughout the core domain.

## Factories, Not Type Parameters

Storage interfaces use `func() any` factories when Kayan needs a fresh model instance:

```go
factory := func() any { return &User{} }
ident, err := repo.FindIdentity(factory, map[string]any{"email": email})
```

This is the mechanism that makes BYOS work without generics. A storage adapter receives a concrete instance it can populate, while `core/` remains decoupled from your type.

## Storage Responsibilities

Your storage implementation should translate between Kayan operations and your schema:

- `CreateIdentity` persists your identity record.
- `FindIdentity` resolves an identity from queries such as identifier lookups.
- `CreateCredential` and `GetCredentialByIdentifier` persist and resolve auth credentials.
- `UpdateCredentialSecret` rotates secrets for password resets, TOTP, or similar flows.

If you use `kgorm`, these patterns are already implemented for the default models and common BYOS mappings. If you build a custom adapter, keep that adapter in the storage layer rather than leaking database logic into `core/` packages.

## Identity Shapes That Work Well

### Single-table identity

Use a single table when your app stores password hash, verification state, roles, and profile traits in one row.

### Identity plus credentials

Use a separate credentials table when you need multiple factors or multiple identifiers per identity, for example password plus WebAuthn plus TOTP.

### Tenant-scoped identity

Store tenant ID in your application schema or storage adapter. Kayan's tenant package handles resolution and scoping, but it does not force a tenant field into the core default identity type.

## Practical Recommendations

- Keep your identity model small and expose capability interfaces only where needed.
- Put field mapping logic in strategy setup, not deep inside handlers.
- Use traits for flexible profile and protocol claim data, not for every first-class domain field.
- If your IDs are not strings, ensure your repository and handlers preserve the type instead of stringifying too early.
- Test your BYOS model with the same flows you use in production. The tests in `core/flow/byos_test.go` are the right pattern to copy.

## Failure Modes to Avoid

- Do not cast everything to `*identity.Identity` in application code. Treat the default model as an example, not a requirement.
- Do not add generics to core extensions. The repository rules explicitly reject that design.
- Do not make optional interfaces mandatory in your custom adapters unless your own application architecture requires them.