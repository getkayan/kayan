# Kayan Examples

The `examples/` directory is the fastest way to move from documentation to a runnable integration.

Each numbered example focuses on one capability and usually includes:

- `backend/` - a Go service wired to the relevant Kayan packages
- `frontend/` - a small demo UI for manual testing when the flow benefits from it

## Suggested Order

1. `01-password` - password registration and login
2. `02-magic-link` - email-based passwordless login
3. `03-totp` - time-based one-time passwords
4. `04-webauthn` - passkeys and WebAuthn ceremonies
5. `05-sms-otp` - SMS one-time passwords
6. `06-social-login` - external identity provider login
7. `07-api-key` - machine-oriented authentication
8. `08-recovery-codes` - backup-factor recovery flows
9. `09-email-otp` - email one-time passwords
10. `10-ldap` - LDAP-backed identity lookup
11. `11-kayan-oidc` - OIDC-oriented integration flow
12. `12-production` - PostgreSQL, Redis, persistent RBAC, admin, and sessions

## Run a Backend Example

From the repository root:

```bash
cd examples/01-password/backend
go run .
```

Swap `01-password` for any other example directory when exploring a different flow.

## Choosing an Example

- Start with `01-password` if you want the smallest complete auth flow.
- Move to `02-magic-link`, `03-totp`, or `04-webauthn` when evaluating passwordless or MFA flows.
- Use `11-kayan-oidc` when you need a fuller protocol-oriented reference.
- Use `12-production` when wiring users, login, sessions, roles, permissions,
  audit, and administration for a real application.

For the quickest library-first onboarding path, pair these examples with `docs/QUICKSTART.md` and `docs/getting-started.md`.
