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

There is no mixed-version persistence migration from the 0.1 development
adapters. Pre-1.0 adopters should migrate application-owned data using their
own schema tooling, switch imports and adapters, then run the shared storage
contract suite before deployment.
