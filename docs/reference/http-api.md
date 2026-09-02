# HTTP API contract

Kayan is a headless Go library. It does not register routes, select an HTTP
framework, start a server, serialize protocol results, or write to an
`http.ResponseWriter`.

The repository's [OpenAPI document](../openapi/openapi.yaml) is an
implementation-neutral reference contract for applications that choose to
expose Kayan through HTTP. It is not proof that a route exists, and importing a
Kayan package does not install any endpoint from the document.

## What the specification covers

The reference contract describes example host endpoints for:

- registration, login, identity inspection, logout, and session refresh;
- OIDC, WebAuthn, SAML, MFA, and account recovery flows;
- OAuth 2.0 authorization, token, introspection, and revocation;
- liveness, readiness, and aggregate health;
- administrative user and user-session operations.

Use it to generate transport models, client code, or an API documentation UI
for a host application. The host remains responsible for adapting request and
response models to Kayan's managers and protocol parsers.

## What it does not define

The OpenAPI document is not the contract for the exported Go packages. The
[Go API index](./go-api.md) is the exhaustive source-level inventory; the
module reference pages explain behavior and security invariants.

It also does not replace protocol discovery documents. OAuth 2.0 and OIDC
metadata must be generated from the provider configuration, while SAML and
SCIM metadata come from their respective packages.

The remote administration routes used by `kayan-cli` extend beyond the
currently described OpenAPI admin paths. Their implemented request mapping is
documented in the [CLI reference](./cli.md). A host may expose a different
administration API and omit the CLI entirely.

## Host implementation requirements

A production HTTP adapter should:

1. authenticate and authorize administrative requests before invoking an
   admin manager;
2. resolve the tenant and carry it in `context.Context` before storage access;
3. pass the request context to every manager, strategy, and store call;
4. map typed and sentinel errors to stable, generic HTTP responses without
   exposing tokens, secrets, LDAP diagnostics, or database errors;
5. enforce body limits, content types, timeouts, and rate limits at the
   transport boundary;
6. use the protocol package's parser instead of manually rebuilding validated
   requests;
7. emit audit events for successful and failed sensitive operations; and
8. terminate TLS at a trusted boundary and set secure cookie attributes if
   sessions are transported in cookies.

Framework-specific wiring examples are in
[HTTP Framework Integration](../adapters/http-frameworks.md). The security
assumptions behind that boundary are in the
[Security Model](../architecture/security-model.md).

## Versioning

The OpenAPI contract is versioned separately from Go source compatibility.
Before relying on it as a public service contract, a host should pin a specific
copy, add request/response conformance tests, and define its own deprecation
policy. See the [API stability map](./api-stability.md).
