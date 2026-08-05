# Storage and directory adapters

```go
import (
    gormstore "github.com/getkayan/kayan/kayan-gorm"
    redisstore "github.com/getkayan/kayan/kayan-redis"
    ldapstore "github.com/getkayan/kayan/kayan-ldap"
    kayantesting "github.com/getkayan/kayan/kayan-testing"
)
```

`core` declares storage and directory contracts but implements none of them, and
never imports a sibling module — CI enforces that with `go list -deps` rather
than a grep, because a doc comment mentioning a module is not an import. These
four modules are the implementations. A deployment compiles only the ones it
uses: password authentication against Postgres pulls in no Redis client and no
LDAP library.

`kayan-gorm` persists identities, sessions, credentials, MFA enrollments, device
trust, RBAC assignments, ReBAC tuples, tokens, and audit events, and installs
the callbacks that make tenant isolation architectural rather than per-query.
`kayan-redis` supplies the stores that are wrong in process memory once you run
more than one replica. `kayan-ldap` connects the LDAP strategy to a real
directory over TLS. `kayan-testing` supplies in-memory doubles and the contract
suite a new backend proves itself against — and must never be imported outside a
`_test.go` file.

---

# kayan-gorm

```go
import gormstore "github.com/getkayan/kayan/kayan-gorm"
```

A GORM-based storage adapter supporting PostgreSQL, MySQL, and SQLite.

## Repository

```go
type Repository struct {
    *IdentityRepository
    *SessionRepository
    // Has unexported fields.
}

func NewRepository(db *gorm.DB) *Repository
```

A facade that combines all sub-repositories. It implements `domain.Storage` by
embedding specialized repositories, so one value satisfies the identity, session,
token, and audit contracts at once.

Protocol storage lives with its protocol, not here: OAuth 2.0 in
`kayan-oidc-provider/gormstore` and SCIM in `kayan-scim/gormstore`. A deployment
that only needs password authentication therefore carries no OAuth 2.0 or SCIM
code at all — which is the point of the module split, not an accident of layout.

```go
func (r *Repository) DB() *gorm.DB
```

Returns the underlying GORM connection, for queries this library does not cover.

### Migrations

```go
func (r *Repository) AutoMigrateDev(models ...any) error
```

Creates or updates tables from the Go models. **For development and tests only.**

GORM's `AutoMigrate` cannot drop a column, cannot transform existing rows, keeps
no record of what it ran, and offers no way back. A schema change that turns out
to be wrong cannot be reversed, and on a table holding accounts that is not
recoverable. The failure is not that it errors; it is that it succeeds, leaves
the orphaned column in place, and gives you nothing to roll back to.

```go
func (r *Repository) AutoMigrate(models ...any) error
```

**Deprecated: use `Repository.AutoMigrateDev` for development, or apply the
versioned SQL from `Migrations` in production.** The name did not say which of
those it was for, so it read as the ordinary way to set up a schema and was used
in production deployments where it should never have been. The rename is the
whole fix: the behavior is unchanged, but a method called `AutoMigrateDev` in a
production startup path is visible in review.

```go
func Migrations(dialect string) (fs.FS, error)
```

Returns the SQL migrations for a dialect. They are returned as a filesystem
rather than applied, so the migration runner stays your choice. golang-migrate,
Atlas, goose, dbmate, and a shell script all read a directory of numbered `.sql`
files:

```go
files, err := gormstore.Migrations(gormstore.DialectPostgres)
if err != nil { /* ... */ }

source, err := iofs.New(files, ".")
m, err := migrate.NewWithSourceInstance("iofs", source, databaseURL)
err = m.Up()
```

Naming follows the convention every one of those tools expects:
`NNNN_description.up.sql` and `NNNN_description.down.sql`.

```go
func MigrationNames(dialect string) ([]string, error)
```

Lists the migration files for a dialect, in the order they must be applied. Use
it to log what a deployment is about to run, or to check the bundled set against
what a database has already recorded — a drift check that catches a migration
applied out of band before it causes a confusing failure.

```go
const (
    DialectPostgres = "postgres"
    DialectMySQL    = "mysql"
    DialectSQLite   = "sqlite"
)
```

The dialects with bundled migrations. Postgres is the recommended production
target; SQLite is for development and testing. Passing an unknown dialect
returns an error rather than falling back to a default, since applying Postgres
DDL to MySQL fails in ways that are worse than not starting.

## Tenant isolation

```go
const TenantColumn = "tenant_id"

var ErrTenantIsolationNotRegistered = errors.New("gormstore: tenant isolation is not registered on this database")

func RegisterTenantIsolation(db *gorm.DB) error
```

Installs GORM callbacks that scope every query to the tenant in the context.

Isolation is applied by a callback rather than by each repository method
remembering to add a predicate. Per-method application is how leaks happen: the
one query somebody forgets is the one that returns another customer's rows, and
nothing fails until it does. A callback cannot be forgotten by a new method,
because the new method does not have to do anything to be covered.

```go
db, err := gorm.Open(postgres.Open(dsn), &gorm.Config{})
if err != nil { /* ... */ }
if err := gormstore.RegisterTenantIsolation(db); err != nil { /* ... */ }
repo := gormstore.NewRepository(db)
```

### How the callback works

`RegisterTenantIsolation` registers five callbacks on the `*gorm.DB`:

| Callback | Hook point | Behavior |
|---|---|---|
| `kayan:tenant_query` | before `gorm:query` | adds the tenant predicate |
| `kayan:tenant_update` | before `gorm:update` | adds the tenant predicate |
| `kayan:tenant_delete` | before `gorm:delete` | adds the tenant predicate |
| `kayan:tenant_row` | before `gorm:row` | adds the tenant predicate |
| `kayan:tenant_create` | before `gorm:create` | stamps the ambient tenant |

Each callback runs the same three checks before doing anything.

**First, is the model scoped?** Only models implementing `tenant.Scoped` are
affected, so tables with no tenant dimension — a migrations table, a global
configuration table — are untouched. A model opts in by implementing the
interface, which means the decision is visible on the type rather than buried in
wiring.

**Second, is this deliberate cross-tenant work?** If `tenant.IsSystemContext(ctx)`
is true, the callback returns without adding a predicate. This is the escape
hatch for background jobs, migrations, and administrative reports that genuinely
need every tenant's rows. It is explicit and greppable:
`tenant.WithSystemContext(ctx)` appears at the call site, so an audit of
cross-tenant access is a search rather than an analysis.

**Third, is there a tenant?** `tenant.RequireID(ctx)` resolves the ambient
tenant. If there is none, the callback calls `db.AddError(tenant.ErrNoTenant)`
and returns — **the query fails rather than running unscoped.**

That last branch is the fail-closed behavior the whole design exists for. An
adapter that silently drops the predicate returns every tenant's rows to a caller
who believes they asked a narrow question, and the result looks like correct data
in the wrong quantity. A caller who forgets to put a tenant in the context gets
an error at the first query, which is loud, immediate, and fixed in minutes.

For scoped models, the net effect is:

- reads, updates, and deletes gain a `tenant_id` predicate;
- inserts are stamped with the ambient tenant;
- a query with no tenant in the context fails, rather than running unscoped.

This is also why every storage and strategy method takes a `context.Context`.
Not for style — the ambient tenant lives in the context, so a method without one
cannot be tenant-scoped. Isolation is architecturally impossible without it.

`ErrTenantIsolationNotRegistered` reports that a tenant-scoped model was used on
a database with no isolation callbacks. It is the same fail-closed reflex applied
one level up: using a scoped model on an unprotected connection is refused rather
than run.

## Identity and session repositories

```go
type IdentityRepository struct {
    // Has unexported fields.
}

func NewIdentityRepository(db *gorm.DB) *IdentityRepository

func (r *IdentityRepository) CreateIdentity(ctx context.Context, ident any) error
func (r *IdentityRepository) GetIdentity(ctx context.Context, factory func() any, id any) (any, error)
func (r *IdentityRepository) UpdateIdentity(ctx context.Context, ident any) error
func (r *IdentityRepository) DeleteIdentity(ctx context.Context, factory func() any, id any) error
func (r *IdentityRepository) FindIdentity(ctx context.Context, factory func() any, query map[string]any) (any, error)
func (r *IdentityRepository) ListIdentities(ctx context.Context, factory func() any, page, limit int) ([]any, error)

func (r *IdentityRepository) CreateCredential(ctx context.Context, cred any) error
func (r *IdentityRepository) GetCredentialByIdentifier(ctx context.Context, identifier string, method string) (*identity.Credential, error)
func (r *IdentityRepository) UpdateCredentialSecret(ctx context.Context, identityID, method, secret string) error
```

The `factory func() any` parameter is BYOS in the type signature. There is no
generic parameter and no base struct to embed: the repository decodes into
whatever the factory returns.

`FindIdentity` takes a map keyed by **Go struct field names**, matched by
reflection, not by database column names.

```go
type SessionRepository struct {
    // Has unexported fields.
}

func NewSessionRepository(db *gorm.DB) *SessionRepository

func (r *SessionRepository) CreateSession(ctx context.Context, s *identity.Session) error
func (r *SessionRepository) GetSession(ctx context.Context, id any) (*identity.Session, error)
func (r *SessionRepository) DeleteSession(ctx context.Context, id any) error
func (r *SessionRepository) GetSessionByRefreshToken(ctx context.Context, token string) (*identity.Session, error)
```

## Tokens and audit

```go
func (r *Repository) SaveToken(ctx context.Context, token *domain.AuthToken) error
func (r *Repository) GetToken(ctx context.Context, token string) (*domain.AuthToken, error)
func (r *Repository) DeleteToken(ctx context.Context, token string) error
func (r *Repository) DeleteExpiredTokens(ctx context.Context) error
```

`GetToken` reports expired tokens as not found. These tokens authenticate
password recovery, email verification, and magic-link login, so the store filters
on expiry rather than relying on every caller to re-check it. A caller who forgot
would accept an expired password-reset token, which is an account takeover
through a link in an old email.

```go
func (r *Repository) SaveEvent(ctx context.Context, event *audit.AuditEvent) error
func (r *Repository) Query(ctx context.Context, filter audit.Filter) ([]audit.AuditEvent, error)
func (r *Repository) Count(ctx context.Context, filter audit.Filter) (int64, error)
func (r *Repository) Export(ctx context.Context, filter audit.Filter, format audit.ExportFormat) (io.Reader, error)
func (r *Repository) Purge(ctx context.Context, olderThan time.Time) (int64, error)
```

`Export` returns an `io.Reader` rather than writing to a `ResponseWriter`, which
keeps transport the caller's and lets a large export stream rather than buffer.

## MFARepository

```go
type MFARepository struct {
    // Has unexported fields.
}

func NewMFARepository(db *gorm.DB, opts ...MFAOption) *MFARepository

type MFAOption func(*MFARepository)

func WithMFAClock(c domain.Clock) MFAOption
```

Persists MFA enrollments, challenges, and recovery codes, implementing
`mfa.MFAStore`. It replaces the in-memory store for production use: MFA
enrollments held in process memory vanish on restart, which locks every enrolled
user out of their own account — the worst kind of outage, because the recovery
path is also gone.

```go
func (r *MFARepository) AutoMigrate() error

func (r *MFARepository) SaveEnrollment(ctx context.Context, enrollment *mfa.Enrollment) error
func (r *MFARepository) GetEnrollment(ctx context.Context, id string) (*mfa.Enrollment, error)
func (r *MFARepository) GetEnrollmentsByIdentity(ctx context.Context, identityID string) ([]*mfa.Enrollment, error)
func (r *MFARepository) UpdateEnrollment(ctx context.Context, enrollment *mfa.Enrollment) error
func (r *MFARepository) DeleteEnrollment(ctx context.Context, id string) error

func (r *MFARepository) SaveChallenge(ctx context.Context, challenge *mfa.Challenge) error
func (r *MFARepository) GetChallenge(ctx context.Context, id string) (*mfa.Challenge, error)
func (r *MFARepository) DeleteChallenge(ctx context.Context, id string) error
func (r *MFARepository) DeleteExpiredChallenges(ctx context.Context) (int64, error)

func (r *MFARepository) SaveRecoveryCodes(ctx context.Context, identityID string, codes []string) error
func (r *MFARepository) GetRecoveryCodes(ctx context.Context, identityID string) ([]string, error)
func (r *MFARepository) ConsumeRecoveryCode(ctx context.Context, identityID, codeHash string) error
```

Three of these carry security properties worth stating explicitly.

`GetChallenge` reports an expired challenge as not found. A challenge is a
single-use authentication step, so serving one past its expiry would let a
captured challenge be completed later.

`ConsumeRecoveryCode` marks the code consumed rather than deleting it, and the
update is conditional on it still being unconsumed. Two concurrent redemptions of
the same code therefore cannot both succeed — the second update matches zero rows
and reports failure. A read-then-write implementation has a window between the
two operations that a parallel request fits through, and a recovery code redeemed
twice is a second-factor bypass.

`SaveRecoveryCodes` replaces any existing codes for the identity, which is what
regenerating means: the old set must stop working. The values are hashes produced
by `mfa.Manager`, never the codes themselves — a database disclosure otherwise
hands over a working second factor for every enrolled user.

`GetRecoveryCodes` returns only unconsumed codes, so a code cannot be redeemed
twice.

`DeleteExpiredChallenges` removes challenges past their expiry. Expired
challenges are already unusable; this only stops the table growing.

## DeviceRepository

```go
type DeviceRepository struct {
    // Has unexported fields.
}

func NewDeviceRepository(db *gorm.DB) *DeviceRepository

func (r *DeviceRepository) AutoMigrate() error

func (r *DeviceRepository) SaveDevice(ctx context.Context, d *device.Device) error
func (r *DeviceRepository) GetDevice(ctx context.Context, id string) (*device.Device, error)
func (r *DeviceRepository) GetDeviceByFingerprint(ctx context.Context, identityID, fingerprint string) (*device.Device, error)
func (r *DeviceRepository) GetDevicesByIdentity(ctx context.Context, identityID string) ([]*device.Device, error)
func (r *DeviceRepository) UpdateDevice(ctx context.Context, d *device.Device) error
func (r *DeviceRepository) DeleteDevice(ctx context.Context, id string) error
func (r *DeviceRepository) DeleteDevicesByIdentity(ctx context.Context, identityID string) error
```

Persists device trust records, implementing `device.Store`. It replaces the
in-memory store for production use: device trust held in process memory is lost
on restart, so every returning user is treated as arriving on a new device and
challenged again.

`DeleteDevicesByIdentity` is what "sign out everywhere" and "forget my devices"
run, so it must remove every record rather than only the current one. A user
reaching for that button believes a device was compromised; leaving any trusted
device behind means the attacker's device may be the one that survived.

## RBAC repository

```go
type RBACRepository struct {
    // Has unexported fields.
}

func NewRBACRepository(db *gorm.DB) *RBACRepository

func (r *RBACRepository) GetIdentityRoles(identityID any) ([]string, error)
func (r *RBACRepository) SetIdentityRoles(identityID any, roles []string) error

type RoleAssignment struct {
    ID         uint   `gorm:"primaryKey;autoIncrement"`
    IdentityID string `gorm:"index:idx_role_identity;not null"`
    Role       string `gorm:"index:idx_role_identity;not null"`
}

func (RoleAssignment) TableName() string
```

Implements `rbac.RBACStorage`. `SetIdentityRoles` replaces all roles for an
identity in a single transaction, so a role change is never observed
half-applied: there is no instant at which the old roles are removed and the new
ones are not yet present. Without the transaction, a concurrent authorization
check during a role update can see an empty role set and deny access to a user
who has permission — a silent wrong denial whose behavior depends on timing.

Note that these two methods take no `context.Context`, unlike the rest of the
module. That makes them unable to participate in tenant scoping through the
ambient context, which is a known rough edge rather than a design decision.

## ReBAC repository

```go
type ReBACRepository struct {
    // Has unexported fields.
}

func NewReBACRepository(db *gorm.DB) *ReBACRepository

func (r *ReBACRepository) AutoMigrate() error

func (r *ReBACRepository) WriteTuple(ctx context.Context, tuple rebac.Tuple) error
func (r *ReBACRepository) WriteTuples(ctx context.Context, tuples []rebac.Tuple) error
func (r *ReBACRepository) ReadTuples(ctx context.Context, filter rebac.TupleFilter) ([]rebac.Tuple, error)
func (r *ReBACRepository) TupleExists(ctx context.Context, tuple rebac.Tuple) (bool, error)
func (r *ReBACRepository) DeleteTuple(ctx context.Context, tuple rebac.Tuple) error
func (r *ReBACRepository) DeleteTuples(ctx context.Context, filter rebac.TupleFilter) error
```

Implements `rebac.Store`, providing persistent storage for relationship tuples.
`WriteTuples` creates multiple tuples atomically, so a permission grant expressed
as several tuples is never half-present.

`core/rebac` has a documented gap worth repeating here: `ListDirectObjects`
returns direct grants only and does not walk the relation graph, so it can omit
access that `Check` allows. `Check` is the authoritative answer.

## Storage registry

```go
type DialectorOpener = func(string) gorm.Dialector

func Register(name string, provider any)
func NewStorage(name string, dsn string, extra any, models ...any) (domain.Storage, error)
```

A registry for constructing storage from configuration rather than from code.
`Register` adds a provider under a name; the provider can be a `DialectorOpener`
(for GORM) or a custom factory function matching
`func(string, any) (domain.Storage, error)`. `NewStorage` constructs an
implementation by that name, returning an error for an unregistered one.

For a `DialectorOpener` provider, `extra` is an optional `*gorm.Config`; pass
`nil` to accept GORM's defaults, and `models` are auto-migrated during
construction. That auto-migration is the reason to be careful with this path in
production: it runs the same GORM `AutoMigrate` that `AutoMigrateDev` documents
as development-only, so a service constructed through the registry migrates its
own schema at startup with no record of what ran and no way back. Prefer opening
the `*gorm.DB` yourself, applying versioned migrations from `Migrations`, and
calling `NewRepository`.

This exists so a deployment can select its database from an environment variable
without the binary importing every driver. It is the only reflective seam in the
module, and it is worth preferring `NewRepository` with an explicitly opened
`*gorm.DB` when the database is known at build time — the direct path gives you a
compile error for a missing driver rather than a runtime one, and it is the path
where you can call `RegisterTenantIsolation` on the connection before using it.

## Convenience constructors

```go
func NewDefaultLoginManager(db *gorm.DB) *flow.LoginManager
func NewDefaultRegistrationManager(db *gorm.DB) *flow.RegistrationManager
func NewDefaultSessionManager(db *gorm.DB) *session.Manager
func NewDefaultOIDCManager(db *gorm.DB, configs map[string]config.OIDCProvider) (*flow.OIDCManager, error)
```

These wire a manager over the default identity model and a GORM connection, for
getting started quickly. They pick the identity model for you, which is the one
thing BYOS otherwise leaves to you, so an application with its own user struct
should construct the managers directly.

---

# kayan-redis

```go
import redisstore "github.com/getkayan/kayan/kayan-redis"
```

Redis-backed implementations of the store interfaces whose in-memory versions are
wrong once more than one replica is running. Every store here exists because the
in-process alternative silently degrades rather than failing: a rate limiter that
is per-replica permits N times the configured rate, and nothing reports it.

## RedisSessionStore

```go
type RedisSessionStore struct {
    // Has unexported fields.
}

func NewRedisSessionStore(client *redis.Client, opts ...SessionStoreOption) *RedisSessionStore

func (s *RedisSessionStore) CreateSession(sess *identity.Session) error
func (s *RedisSessionStore) GetSession(id any) (*identity.Session, error)
func (s *RedisSessionStore) GetSessionByRefreshToken(token string) (*identity.Session, error)
func (s *RedisSessionStore) DeleteSession(id any) error
```

Implements `domain.SessionStorage`. Sessions are stored as a Redis hash with a
separate refresh-token mapping, so `GetSessionByRefreshToken` is a lookup rather
than a scan.

```go
type SessionStoreOption func(*RedisSessionStore)

func WithSessionPrefix(prefix string) SessionStoreOption
func WithSessionTTL(ttl time.Duration) SessionStoreOption
```

`WithSessionPrefix` sets the key prefix, which is how several applications share
a Redis instance without colliding. `WithSessionTTL` sets the TTL for session
keys, so Redis expires abandoned sessions rather than accumulating them.

Note that these methods take no `context.Context`, matching the
`domain.SessionStorage` interface they implement.

## RedisRateLimiter

```go
type RedisRateLimiter struct {
    // Has unexported fields.
}

func NewRedisRateLimiter(client *redis.Client, prefix string) *RedisRateLimiter

func (r *RedisRateLimiter) Allow(ctx context.Context, key string, limit int, window time.Duration) (bool, int, error)
func (r *RedisRateLimiter) Reset(ctx context.Context, key string) error
```

Implements `flow.RateLimiter` using a sliding window log algorithm, which is more
accurate at the window boundary than a fixed counter: a fixed-window limiter
permits twice the configured rate across the instant the window rolls over, which
is exactly when a credential-stuffing run would concentrate its attempts.

`Allow` returns whether the request is permitted and how many remain. An
in-memory limiter across N replicas permits N times the configured rate, which is
the whole reason this store exists.

## RedisLockoutStore

```go
type RedisLockoutStore struct {
    // Has unexported fields.
}

func NewRedisLockoutStore(client *redis.Client, prefix string) *RedisLockoutStore

func (s *RedisLockoutStore) RecordFailure(ctx context.Context, identifier string, ttl time.Duration) (int, error)
func (s *RedisLockoutStore) IsLocked(ctx context.Context, identifier string) (bool, time.Time, error)
func (s *RedisLockoutStore) Lock(ctx context.Context, identifier string, duration time.Duration) error
func (s *RedisLockoutStore) ClearFailures(ctx context.Context, identifier string) error
```

Implements `flow.LockoutStore` for distributed brute-force lockout tracking.
`RecordFailure` increments the count and returns the new value; `IsLocked`
reports the lock state and when it expires.

Per-replica lockout counting is the same failure as per-replica rate limiting:
five attempts per replica across four replicas is twenty attempts, and an
attacker distributing requests across a load balancer gets them for free.

`ClearFailures` resets the count and belongs on the successful-authentication
path, so a user who mistypes their password twice and then succeeds does not
carry those failures toward a future lockout.

## RedisWebAuthnSessionStore

```go
type RedisWebAuthnSessionStore struct {
    // Has unexported fields.
}

func NewRedisWebAuthnSessionStore(client *redis.Client, prefix string) *RedisWebAuthnSessionStore

func (s *RedisWebAuthnSessionStore) SaveSession(ctx context.Context, sessionID string, data *flow.WebAuthnSessionData) error
func (s *RedisWebAuthnSessionStore) GetSession(ctx context.Context, sessionID string) (*flow.WebAuthnSessionData, error)
func (s *RedisWebAuthnSessionStore) DeleteSession(ctx context.Context, sessionID string) error
```

Implements `flow.WebAuthnSessionStore`. A WebAuthn ceremony spans two requests:
the server issues a challenge, and the authenticator's signed response arrives
separately. The challenge must be retrievable on the second request, and with
in-memory storage that only works when both requests land on the same replica —
so registration and login fail intermittently at a rate set by your replica
count.

`DeleteSession` must be called after the ceremony completes. The challenge is
single-use; retaining it lets a captured assertion be replayed.

---

# kayan-ldap

```go
import ldapstore "github.com/getkayan/kayan/kayan-ldap"
```

Connects Kayan's LDAP strategy to a real directory server. `core/flow` declares
`flow.LDAPDialer` and `flow.LDAPConn` but deliberately never imports an LDAP
library, so an application that does not use LDAP does not link one. This package
supplies the implementation, backed by `github.com/go-ldap/ldap/v3`.

```go
dialer := ldapstore.NewDialer()
strategy := flow.NewLDAPStrategy(dialer, flow.LDAPConfig{
    Addr:                   "ldap.example.com:636",
    BaseDN:                 "ou=users,dc=example,dc=com",
    UsernameAttribute:      "uid",
    ServiceAccountDN:       "cn=svc,dc=example,dc=com",
    ServiceAccountPassword: os.Getenv("LDAP_SERVICE_PASSWORD"),
    TraitAttributes:        map[string]string{"email": "mail"},
}, func() any { return &User{} })

loginManager.RegisterStrategy(strategy)
```

## TLS is required

`Dialer.DialTLS` requires TLS. LDAP simple bind sends the password in the clear,
so an unencrypted connection would expose every credential it carries — not the
hash, the password, to anyone on the path. Certificate verification is on by
default and can only be weakened through explicit options that document what they
give up.

There is no plaintext dial method on this type. That is deliberate: an option to
disable TLS would be reached for during a development setup and then survive into
production, where it turns the directory connection into a credential feed for
anyone able to observe the network.

```go
var ErrTLSRequired = errors.New("ldapstore: TLS is required")
```

```go
const DefaultTimeout = 10 * time.Second
```

Bounds connection and search operations when no timeout is configured. An
unbounded directory call is how a slow LDAP server turns into an exhausted
connection pool in the application in front of it.

## Dialer

```go
type Dialer struct {
    // Has unexported fields.
}

func NewDialer(opts ...DialerOption) *Dialer

func (d *Dialer) DialTLS(ctx context.Context, addr string) (flow.LDAPConn, error)
```

Opens TLS connections to an LDAP server, implementing `flow.LDAPDialer`. **The
zero value is not usable; call `NewDialer`.**

`NewDialer` returns a dialer that requires TLS 1.2 or better and verifies the
server certificate against the platform roots.

`DialTLS` returns a connection that is closed when `ctx` is cancelled, so a
caller that abandons a login does not leak a directory connection.

## DialerOption

```go
type DialerOption func(*Dialer)
```

```go
func WithTLSConfig(cfg *tls.Config) DialerOption
```

Replaces the TLS configuration entirely. Use this to pin a corporate CA or
present a client certificate:

```go
pool := x509.NewCertPool()
pool.AppendCertsFromPEM(caPEM)
ldapstore.NewDialer(ldapstore.WithTLSConfig(&tls.Config{RootCAs: pool}))
```

Because it replaces rather than merges, a configuration passed here decides the
minimum TLS version too. Set `MinVersion: tls.VersionTLS12` explicitly, or you
lose the default floor.

```go
func WithRootCAs(pool *x509.CertPool) DialerOption
```

Trusts `pool` **in addition to** the platform roots. This is the option for an
internal CA, and the one to prefer over `WithTLSConfig` when trusting an extra CA
is all you need — it keeps every other default in place.

```go
func WithTimeout(d time.Duration) DialerOption
```

Bounds connection and search operations. Defaults to `DefaultTimeout`.

```go
func WithInsecureSkipVerify() DialerOption
```

Disables certificate verification. **This makes the connection trivially
interceptable: an attacker who can answer for the server address receives every
password bound through it.** It exists for development against a self-signed
directory. Never enable it in production — use `WithRootCAs` to trust an internal
CA instead, which solves the same self-signed-certificate problem without
removing authentication of the server.

## Conn

```go
type Conn struct {
    // Has unexported fields.
}

func (c *Conn) Bind(dn, password string) error
func (c *Conn) Search(req flow.LDAPSearchRequest) ([]flow.LDAPEntry, error)
func (c *Conn) Close() error
```

An active LDAP connection, implementing `flow.LDAPConn`.

`Bind` authenticates on the connection. The password is passed to the server and
never logged, stored, or included in a returned error. That last clause is the
one that matters in practice: an error string containing the attempted password
ends up in log aggregation, where it is retained far longer and read by far more
people than the credential store ever would be.

`Close` releases the connection and stops the context watcher.

---

# kayan-testing

```go
import kayantesting "github.com/getkayan/kayan/kayan-testing"
```

In-memory implementations of Kayan's storage contracts, plus a contract test
suite any implementation can run.

## Tests only

**`kayan-testing` must never be imported outside a `_test.go` file.** CI enforces
that, and the enforcement is not pedantry: everything here keeps state in process
memory and is lost on restart. A `MemoryStore` reached in production means every
identity, session, credential, and audit event disappears on the next deploy, and
the symptom — every user is suddenly unregistered — arrives at whatever hour the
deploy happened.

The module exists so tests and examples do not each hand-roll a store, and so a
new backend can prove it satisfies the same contract the bundled adapters do.

## MemoryStore

```go
type MemoryStore struct {
    // Has unexported fields.
}

func NewMemoryStore(opts ...MemoryStoreOption) *MemoryStore

type MemoryStoreOption func(*MemoryStore)

func WithClock(c domain.Clock) MemoryStoreOption
```

An in-memory `domain.Storage`. It is safe for concurrent use. Stored values are
the caller's pointers, not copies, matching how the GORM adapter behaves after a
write — a test that mutates a struct it stored sees the mutation reflected, which
is what the real adapter does too, so a test does not pass against the double and
fail against Postgres.

`WithClock` sets the clock used for timestamps, defaulting to
`domain.SystemClock`. Pair it with `FakeClock` to test expiry.

```go
func (s *MemoryStore) CreateIdentity(ctx context.Context, ident any) error
func (s *MemoryStore) GetIdentity(ctx context.Context, _ func() any, id any) (any, error)
func (s *MemoryStore) UpdateIdentity(ctx context.Context, ident any) error
func (s *MemoryStore) DeleteIdentity(ctx context.Context, _ func() any, id any) error
func (s *MemoryStore) FindIdentity(ctx context.Context, _ func() any, query map[string]any) (any, error)
func (s *MemoryStore) ListIdentities(ctx context.Context, _ func() any, page, limit int) ([]any, error)

func (s *MemoryStore) CreateCredential(ctx context.Context, cred any) error
func (s *MemoryStore) GetCredentialByIdentifier(ctx context.Context, identifier, method string) (*identity.Credential, error)
func (s *MemoryStore) UpdateCredentialSecret(_ context.Context, identityID, method, secret string) error

func (s *MemoryStore) CreateSession(ctx context.Context, sess *identity.Session) error
func (s *MemoryStore) GetSession(ctx context.Context, id any) (*identity.Session, error)
func (s *MemoryStore) GetSessionByRefreshToken(ctx context.Context, token string) (*identity.Session, error)
func (s *MemoryStore) DeleteSession(ctx context.Context, id any) error

func (s *MemoryStore) SaveToken(_ context.Context, token *domain.AuthToken) error
func (s *MemoryStore) GetToken(_ context.Context, token string) (*domain.AuthToken, error)
func (s *MemoryStore) DeleteToken(_ context.Context, token string) error
func (s *MemoryStore) DeleteExpiredTokens(context.Context) error

func (s *MemoryStore) SaveEvent(_ context.Context, event *audit.AuditEvent) error
func (s *MemoryStore) Query(_ context.Context, filter audit.Filter) ([]audit.AuditEvent, error)
func (s *MemoryStore) Count(_ context.Context, filter audit.Filter) (int64, error)
func (s *MemoryStore) Purge(_ context.Context, olderThan time.Time) (int64, error)
func (s *MemoryStore) Export(context.Context, audit.Filter, audit.ExportFormat) (io.Reader, error)

func (s *MemoryStore) Events() []audit.AuditEvent
func (s *MemoryStore) Reset()
```

Behavior worth knowing when writing assertions:

`GetToken` reports expired tokens as not found, matching a store that filters on
expiry. A test asserting that an expired recovery token is refused passes here
for the same reason it passes against Postgres.

`FindIdentity` matches on **Go struct field names**, by reflection, exactly as the
GORM adapter and the flow strategies expect.

`GetIdentity` accepts the factory for parity with the storage contract but
ignores it; the stored value is returned as-is, since an in-memory store has
nothing to decode.

`ListIdentities` uses 1-based pages, and a limit of zero or less returns every
identity. Order is not specified, matching a store with no explicit sort — so a
test asserting a particular order is asserting something neither implementation
promises.

`Count` ignores pagination and reports how many events match, which is what a
caller needs to compute the number of pages.

`Export` is not implemented; `MemoryStore` is a test double, and export
formatting belongs to real adapters.

`Events` returns a copy of every recorded audit event, for assertions. `Reset`
empties the store, so one instance can serve several subtests.

```go
var (
    ErrNotFound      = errors.New("kayantesting: not found")
    ErrAlreadyExists = errors.New("kayantesting: already exists")
)
```

These match the wording storage adapters conventionally use, so tests asserting
on them behave the same either way.

## FakeClock

```go
type FakeClock struct {
    // Has unexported fields.
}

func NewFakeClock(t time.Time) *FakeClock

func (c *FakeClock) Now() time.Time
func (c *FakeClock) Advance(d time.Duration)
func (c *FakeClock) Set(t time.Time)
```

A `domain.Clock` whose time only moves when told. It is safe for concurrent use.

It exists so validity windows can be tested at their exact boundary rather than by
sleeping:

```go
clock := kayantesting.NewFakeClock(time.Now())
token := issue(clock.Now())
clock.Advance(ttl - time.Nanosecond)
// still valid
clock.Advance(time.Nanosecond)
// now expired
```

A test that sleeps to reach an expiry is slow and flaky, and — worse — usually
tests a window far from the boundary, so an off-by-one in the comparison passes.
Driving the clock to the exact nanosecond is what catches `>` where `>=` belonged.

`Advance` accepts a negative duration, which moves the clock backwards. That is
how you test clock skew tolerance: a SAML assertion or a JWT whose `NotBefore` is
slightly ahead of local time must be accepted within the skew window and refused
outside it.

Every seam that reads time in Kayan takes a `domain.Clock` — `WithProviderClock`,
`WithServerClock`, `WithSPClock`, `WithIdPClock`, `WithMFAClock`, `WithClock` —
so this drives all of them.

## StorageSuite

```go
func StorageSuite(t *testing.T, newStore func() domain.Storage)
```

Runs the `domain.Storage` contract against an implementation. This is how a new
backend proves it behaves like the bundled ones:

```go
func TestMongoStore(t *testing.T) {
    kayantesting.StorageSuite(t, func() domain.Storage {
        return mongostore.New(testDatabase(t))
    })
}
```

`newStore` must return a **fresh, empty store on each call**; the suite calls it
once per subtest so failures cannot cascade. A constructor that returns a shared
instance makes one subtest's leftover data another subtest's failure, and the
resulting report points at the wrong method.

A store that needs schema prepared for the caller's identity model — a SQL
adapter, say — should migrate `SuiteIdentity` inside `newStore`:

```go
kayantesting.StorageSuite(t, func() domain.Storage {
    db := openTestDB(t)
    if err := db.AutoMigrate(&kayantesting.SuiteIdentity{}); err != nil {
        t.Fatal(err)
    }
    return gormstore.New(db)
})
```

The suite asserts behavior the rest of Kayan depends on. It deliberately does not
assert error identity — adapters return their own error values — only whether an
operation succeeds or fails. Requiring a specific sentinel would force every
backend to translate its native errors into Kayan's, which is work that buys
nothing: the callers in `core/flow` branch on success and failure, not on which
error value came back.

```go
func StorageSuiteWithModel(t *testing.T, newStore func() domain.Storage, factory func() any)
```

`StorageSuite` for a store whose identity model is not `SuiteIdentity`.

The model must have string fields named `ID`, `Email`, and `Name`, since the
suite reads and queries those. Use this when the adapter can only persist a type
it already knows, such as one carrying database struct tags.

## SuiteIdentity

```go
type SuiteIdentity struct {
    ID    string
    Email string
    Name  string
    State string
}

func (u *SuiteIdentity) GetID() any
func (u *SuiteIdentity) SetID(id any)
```

The identity model the contract suite stores. It is deliberately plain — no
struct tags, no embedded base type, no generic parameter. Any `domain.Storage`
must handle an arbitrary caller-defined struct, which is what "bring your own
schema" means, and a suite model carrying GORM tags would let an adapter pass by
depending on tags a real caller's struct does not have.
