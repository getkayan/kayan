# CLI reference

`kayan-cli` is an experimental command-line client and project scaffolder. It
is not part of the importable Go API, and Kayan does not start the HTTP server
that its remote commands call. Your host application must expose the expected
administration routes described below.

## Installation and configuration

Build the command from the repository root:

```console
go build -o kayan-cli ./cmd/kayan-cli
```

Remote commands read two environment variables:

| Variable | Meaning | Default |
|---|---|---|
| `KAYAN_URL` | Base URL of the host application's administration API | `http://localhost:8080` |
| `KAYAN_TOKEN` | Bearer token sent in `Authorization` | unset |

The client uses JSON request bodies and a 30-second HTTP timeout. HTTP status
codes of 400 or greater produce a non-zero exit. The response body is included
in the local error message, so the host must never return secrets or sensitive
internal diagnostics in an error response.

`KAYAN_TOKEN` is optional only at the client layer. A production host should
require an authenticated, authorized administrator for every `/admin` route.

## User commands

| Command | Host request | Options/body |
|---|---|---|
| `user list` | `GET /admin/users` | `--limit`, `--offset`, `--tenant`, `--q` |
| `user get ID` | `GET /admin/users/ID` | none |
| `user create` | `POST /admin/users` | required `--email`; optional `--password`, `--tenant` |
| `user update ID` | `PATCH /admin/users/ID` | optional `--email`, `--state` |
| `user delete ID` | `DELETE /admin/users/ID` | none |
| `user lock ID` | `POST /admin/users/ID/lock` | optional `--reason` |
| `user unlock ID` | `POST /admin/users/ID/unlock` | none |
| `user sessions ID` | `GET /admin/users/ID/sessions` | none |
| `user revoke-sessions ID` | `DELETE /admin/users/ID/sessions` | none |

The list command expects `{ "data": [...], "total": number }`. Other
successful JSON responses are formatted and printed without imposing a schema.

## Tenant commands

| Command | Host request | Options/body |
|---|---|---|
| `tenant list` | `GET /admin/tenants` | `--limit`, `--offset` |
| `tenant get ID` | `GET /admin/tenants/ID` | none |
| `tenant create` | `POST /admin/tenants` | required `--name`; optional `--domain` |
| `tenant update ID` | `PATCH /admin/tenants/ID` | optional `--name`, `--domain` |
| `tenant delete ID` | `DELETE /admin/tenants/ID` | none |

## Role commands

| Command | Host request | Options/body |
|---|---|---|
| `role list` | `GET /admin/roles` | `--limit`, `--offset`, `--tenant` |
| `role get ID` | `GET /admin/roles/ID` | none |
| `role create` | `POST /admin/roles` | required `--name`, `--permissions=P1,P2` |
| `role delete ID` | `DELETE /admin/roles/ID` | none |

Permissions are split at commas without trimming. Use
`--permissions=users.read,users.write`, without spaces.

## Session, audit, and health commands

| Command | Host request | Options |
|---|---|---|
| `session list` | `GET /admin/sessions` | `--limit`, `--offset`, `--user`, `--tenant` |
| `session revoke ID` | `DELETE /admin/sessions/ID` | none |
| `audit query` | `GET /admin/audit` | `--limit`, `--offset`, `--user_id`, `--tenant_id`, `--type` |
| `audit export` | `GET /admin/audit/export` | `--user_id`, `--tenant_id`, `--format=json\|csv` |
| `health live` | `GET /health/live` | none |
| `health ready` | `GET /health/ready` | none |
| `health full` or `health` | `GET /health` | none |

Arguments and identifier path segments are encoded by the current client as
literal text. Until the client percent-encodes them, do not pass untrusted or
delimiter-containing values such as `&`, `=`, `/`, `?`, or `#` through CLI
options or identifiers.

## Local commands

`kayan-cli init [name]` creates a minimal Go module and `main.go`. Review the
generated dependency version before using it: scaffolding is a starting point,
not a dependency lock policy.

`kayan-cli version` prints the build-time version. Release builds set it with
the Go linker; source builds report `dev`.

`kayan-cli generate handler` is currently a placeholder and does not generate
files. It must not be used as part of a production build.

## Compatibility status

The command and flag surface has a checksum test, but the remote response
formats do not yet have complete command-level contract tests. Treat the CLI
as experimental and pin the Kayan version used by automation. See the
[API stability map](./api-stability.md) and the [HTTP contract](./http-api.md).
