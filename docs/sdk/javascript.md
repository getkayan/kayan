# JavaScript and TypeScript Integration

Kayan is a Go library, not a browser or Node.js SDK. JavaScript and TypeScript clients integrate with Kayan indirectly through the transport surface your application exposes.

That means there are two valid frontend integration models.

## 1. Standards-Based Integration

Use this when your Go service exposes protocol endpoints backed by Kayan:

- OAuth 2.0 token endpoints
- OIDC discovery, authorize, token, userinfo, and logout endpoints
- SCIM endpoints for provisioning clients
- SAML browser redirects and ACS handlers for enterprise login

In this model, frontend code talks to standards-compliant endpoints. Kayan stays on the server side.

## 2. Application-Specific API Integration

Use this when your service wraps Kayan flows in your own JSON APIs, for example:

- `/auth/register`
- `/auth/login`
- `/auth/magic-link/start`
- `/auth/mfa/challenge`
- `/auth/mfa/verify`

Your JS client calls those APIs, while the Go service maps them onto `core/flow`, `core/session`, and related packages.

## Example: Password Login

```ts
type LoginRequest = {
  method: "password";
  identifier: string;
  secret: string;
};

type LoginResponse = {
  accessToken?: string;
  refreshToken?: string;
  requiresMfa?: boolean;
  challengeId?: string;
};

export async function login(input: LoginRequest): Promise<LoginResponse> {
  const response = await fetch("/auth/login", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(input),
  });

  if (!response.ok) {
    throw new Error("login failed");
  }

  return response.json();
}
```

On the server, that handler would call `LoginManager.Authenticate` and then issue a session through `core/session`.

## Example: OIDC Client

If your application exposes OIDC endpoints backed by `core/oauth2` and `core/oidc`, use a standard OIDC client library on the JS side. That is usually a better choice than inventing a custom login protocol.

## Security Guidance for Frontends

- prefer authorization-code plus PKCE over implicit-style flows
- do not handle passwords in frontend code if your architecture can delegate to a hosted or redirected login experience
- treat refresh tokens as high-sensitivity credentials
- handle MFA-required states as explicit branch conditions in the client state machine

## Example App

The repository includes `examples/nextjs-kayan-demo`, which is the best place to evolve framework-specific frontend integration examples without pushing frontend assumptions into the core library.