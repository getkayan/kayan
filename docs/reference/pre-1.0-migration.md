# Pre-1.0 migration notes

Kayan's historical `v0.1.0` tags are not the compatibility baseline for 1.0.
They predate the headless multi-module architecture and included infrastructure
and HTTP dependencies in `core`. The reviewed API snapshots in
`api-baseline/` are the start of the proposed 1.0 compatibility contract.

## Intentional breaking changes since 0.1

- The GORM module moved from `github.com/getkayan/kayan/kgorm` to
  `github.com/getkayan/kayan/kayan-gorm`.
- Protocols and infrastructure adapters moved out of `core` into optional
  modules. Applications import only the protocols and adapters they choose.
- Storage contracts use consumer-owned models, `any`, and factories to support
  Bring Your Own Schema rather than prescribed database models.
- `oauth2.TokenResponse` gained `Authentication`, which carries a `[]string`,
  so the struct is no longer comparable with `==`. The field is not serialised;
  it exists because the nonce, `auth_time`, `acr`, and `amr` live on the
  authorization code that `Exchange` consumes and deletes, and nothing handed
  them back.
- `oauth2.AuthCode` gained `AuthTime`, `ACR`, `AMR`, and `MaxAgeSeconds`. An
  `AuthCodeStore` must persist all four, or the token endpoint cannot tell
  whether `max_age` was honoured.
- `saml.Session` gained `RequestedAuthnContexts []string`, so the struct is no
  longer comparable with `==`. A `SessionStore` implementation persisting the
  new field is what makes `ForceAuthn` and `RequestedAuthnContext` enforceable:
  a store that drops it silently turns a step-up back into an ordinary login.
- `domain.TokenStore` requires atomic `ConsumeToken`; adapters must prevent two
  callers from successfully consuming the same transient credential.
- `session.SSOStore` uses atomic create/join/leave/deactivate operations rather
  than manager-side read-modify-write behavior.
- OIDC login uses the transport-neutral `flow.OIDCClient` contract and carries
  state, nonce, PKCE challenge, verifier, and redirect URI explicitly.
- OIDC-provider audit is enabled explicitly with
  `oauth2.WithProviderAudit(store, handler)` so persistence failures are
  observable and the client store is not required to implement audit storage.
- SAML metadata retrieval defaults to public HTTPS URLs. Private IdP metadata
  endpoints require an explicit `WithMetadataURLPolicy` opt-in.
- `admin.Manager.CreateUser` no longer ignores `CreateUserInput.Password` or
  `Roles`. A store must implement `admin.UserProvisioningStore` to commit the
  identity, hashed password, and assignments atomically; otherwise the call
  returns `admin.ErrNotConfigured` before creating the user.
- `LoginManager` now refuses non-active identities implementing
  `flow.IdentityStateSource`. The default `identity.Identity` implements the
  contract. Custom BYOS identities opt in by adding `IdentityState() string`.
- `core/telemetry`, `core/logger`, and `core/config` moved to the optional
  `kayan-observability` module. Only the import path changes:

  ```go
  // before
  import "github.com/getkayan/kayan/core/telemetry"
  // after
  import "github.com/getkayan/kayan/kayan-observability/telemetry"
  ```

  `core` is what every consumer compiles, and these three pulled the
  OpenTelemetry SDK, its gRPC and Prometheus exporters, zap, and viper into
  every deployment's dependency graph -- including deployments that never
  called them. Nothing in `core` imported any of the three. Moving them takes
  `core` from 265 transitive dependencies to 53, and a CI ceiling now fails the
  build if that grows back.

- `flow.OIDCManager`, `flow.NewOIDCManager`, `flow.ClaimMapper`,
  `flow.OIDCProviderData`, and `gormstore.NewDefaultOIDCManager` are removed.
  Use `flow.NewKayanOIDCStrategy` instead.

  `OIDCManager` was a second OIDC relying-party implementation with weaker
  guarantees than the one beside it. Its callback took no `state` parameter, so
  it could not validate CSRF state, and it requested no nonce, so an ID token
  could be replayed. It also linked a federated login to an existing local
  account on a bare `email` claim, without checking `email_verified` -- an
  account takeover at any provider that lets a user assert an address. That
  last one was fixed in place first, so the fix exists in history for anyone
  pinned to an earlier commit, and the type is removed here rather than left
  reachable with a deprecation comment.

  `KayanOIDCStrategy` covers the same flow and carries state, nonce, and PKCE
  explicitly:

  ```go
  strategy := flow.NewKayanOIDCStrategy(
      issuer, clientID, redirectURI,
      oauthClient, tokenParser, repo, factory,
  )
  // Initiate returns the authorization URL with state, nonce, and PKCE.
  // Authenticate(ctx, state, code) validates state before exchanging the code.
  ```

There is no mixed-version persistence migration from the 0.1 development
adapters. Pre-1.0 adopters should migrate application-owned data using their
own schema tooling, switch imports and adapters, then run the shared storage
contract suite before deployment.
