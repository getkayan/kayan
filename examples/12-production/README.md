# Production wiring reference

This is the narrow production candidate Kayan currently proves end to end:

- PostgreSQL identities, credentials, opaque sessions, audit events, roles,
  and role assignments;
- Redis-backed password lockout shared by every replica;
- registration, login, refresh rotation, logout, account-state enforcement;
- persistent RBAC and authorized user/role administration;
- a bootstrap administrator created atomically with its password and role.

It intentionally does not include SAML, SCIM, an OIDC provider, or a frontend.
Those are independent modules, not prerequisites for application IAM.

## Run

Start PostgreSQL and Redis from this directory:

```bash
docker compose up -d
```

The compose file applies Kayan's versioned PostgreSQL migrations only when the
database volume is first created. For an existing database, apply the files
from `kayan-gorm/migrations/postgres` with your migration runner; never call
`AutoMigrateDev` in production.

Then run the backend:

```bash
cd backend
export DATABASE_URL='postgres://kayan:kayan@localhost:5432/kayan?sslmode=disable'
export REDIS_ADDR='localhost:6379'
export BOOTSTRAP_ADMIN_EMAIL='admin@example.com'
export BOOTSTRAP_ADMIN_PASSWORD='ReplaceWithAStrongPassword123'
go run .
```

Remove the bootstrap password from the environment after the first successful
startup. Subsequent starts do not reset an existing administrator.

Self-registration is disabled by default. Set `ALLOW_REGISTRATION=true` only
when your application deliberately exposes `POST /api/register`.

The example returns opaque database-session tokens. Put the service behind TLS
and send the access token only in `Authorization: Bearer ...`. If your browser
application moves it into a cookie, add CSRF protection at the HTTP layer.
