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
