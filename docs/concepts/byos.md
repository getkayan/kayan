# BYOS — Bring Your Own Schema

Your identity model, field names, ID type, and storage topology stay yours.
Kayan stores the struct you already have rather than asking you to adopt one
of its own.

```go
type User struct {
    ID        string `gorm:"primaryKey"`
    Email     string `gorm:"uniqueIndex"`
    TeamID    string
    JoinedAt  time.Time
}

func (u *User) GetID() any   { return u.ID }
func (u *User) SetID(id any) { u.ID = id.(string) }
```

That is the whole contract. No base type to embed, no reserved column names,
no interface with twelve methods.

---

## Why this matters

An identity library that owns your user table owns a great deal more than it
looks like. It decides your primary key type. It decides whether you can add a
foreign key from `orders` to `users`. It decides what a migration looks like
when your product changes. And it usually decides that a user has exactly the
fields the library imagined.

Most teams already have a users table before they have an authentication
problem. Asking them to migrate it — or to maintain a second table that
shadows the first — is a large cost paid for a small convenience.

Kayan takes the other position: **authentication is a behavior applied to your
model, not a schema you adopt.**

---

## How it works without generics

Storage methods take `any` plus a factory function:

```go
type IdentityStorage interface {
    CreateIdentity(ctx context.Context, ident any) error
    GetIdentity(ctx context.Context, factory func() any, id any) (any, error)
    FindIdentity(ctx context.Context, factory func() any, query map[string]any) (any, error)
    // ...
}
```

The factory is how Kayan allocates your type without knowing it:

```go
factory := func() any { return &User{} }

ident, err := repo.GetIdentity(ctx, factory, "user-123")
user := ident.(*User)
```

### Why not generics?

Go generics would give compile-time type safety here, and that is genuinely
better in isolation. They were not used for a specific reason: **a generic
type parameter propagates**.

`Storage[T]` forces `LoginManager[T]`, which forces `Strategy[T]`, which
forces every option, every hook, and every interface a caller implements to
carry `T` as well. A service with two identity models — a `User` and a
`ServiceAccount`, say — ends up with two parallel instantiations of the entire
library, and any code wanting to handle both needs an interface that erases
the parameter again.

The type assertion is a real cost. It is paid once, at the boundary, where you
already know the type. The alternative would be paid everywhere.

This is written down in [AGENTS.md](../../AGENTS.md) as an architectural rule
rather than a preference, because it is the kind of decision that gets
quietly reversed one signature at a time.

---

## What Kayan requires of your model

Only what the operation needs. The interfaces are small and separately
optional, so a model implements what it uses.

### Identity — required

```go
type FlowIdentity interface {
    GetID() any
    SetID(id any)
}
```

`SetID` exists so Kayan can assign a generated identifier during registration.
If you generate IDs yourself — a database sequence, a ULID from your own
code — supply an `IDGenerator` and `SetID` receives that value instead.

### Traits — optional

```go
type TraitSource interface {
    GetTraits() identity.JSON
    SetTraits(traits identity.JSON)
}
```

Traits are a JSON blob for profile data that does not deserve a column. If
your model has real columns for everything, skip this interface and map fields
directly instead.

### Credentials — optional

```go
type CredentialSource interface {
    GetCredentials() []identity.Credential
    SetCredentials(creds []identity.Credential)
}
```

Implement it when credentials live on the identity itself. Most deployments
store them in a separate table, which the storage adapter handles without this
interface.

### Verification and MFA — optional

```go
type VerificationIdentity interface {
    IsVerified() bool
    MarkVerified(time.Time)
}

type MFAIdentity interface {
    MFAConfig() (enabled bool, secret string)
}
```

Each is needed only by the flow that uses it. A service without email
verification never implements the first, and one without TOTP never implements
the second. Kayan checks for them with a type assertion at the point of use
rather than requiring them up front.

---

## Field mapping

`FindIdentity` takes a `map[string]any` keyed by **Go struct field name**, not
column name and not JSON tag:

```go
// Matches the Email field, whatever column it is stored in.
repo.FindIdentity(ctx, factory, map[string]any{"Email": "ada@example.com"})
```

The storage adapter translates to whatever its backend needs — GORM applies
its naming convention, a document store might use the JSON tag.

When the identifying field is not named what Kayan expects, say so at
construction:

```go
// Users are identified by Username, not Email.
reg, login := flow.PasswordAuth(repo, factory, "Username")
```

Or map explicitly on the strategy. `MapFields` takes the identifier fields to
search and the field holding the password hash:

```go
strategy := flow.NewPasswordStrategy(repo, hasher, "Username", factory)

// Accept either field as the login identifier, and read the hash from
// PasswordHash.
strategy.MapFields([]string{"Username", "WorkEmail"}, "PasswordHash")
```

Listing several identifier fields is how a service lets people sign in with
either a username or an email address without storing the same value twice.

---

## ID types

`GetID() any` returns `any` deliberately. String UUIDs, integer sequences, and
ULIDs all work:

```go
type User struct {
    ID int64 `gorm:"primaryKey"`
}

func (u *User) GetID() any { return u.ID }
func (u *User) SetID(id any) {
    switch v := id.(type) {
    case int64:
        u.ID = v
    case string:
        u.ID, _ = strconv.ParseInt(v, 10, 64)
    }
}
```

Handle the type your generator actually produces. If you supply an
`IDGenerator` returning `int64`, `SetID` only ever receives `int64`.

### Two generators, deliberately distinct

```go
type IDGenerator func() any            // record identifiers
type TokenGenerator func() (string, error)  // credentials
```

`IDGenerator` is for record IDs, where any scheme works — UUIDv4, UUIDv7,
ULID, a database sequence. Readability and sort order are reasonable things to
optimize for.

`TokenGenerator` produces authorization codes, refresh tokens, magic links,
and state values. Those are credentials: a sequential or timestamp-derived
value lets an attacker guess one belonging to somebody else.

They are separate types so a generator chosen for readable record IDs cannot
be wired into a credential path by accident. Authorization codes were once
produced by the same generator as record IDs, which meant a caller swapping in
a sequential generator would have made them predictable — with nothing
reporting it.

---

## Your storage, too

`domain.Storage` is an interface. GORM and Redis adapters ship, and nothing
requires you to use them.

```go
type mongoStore struct{ db *mongo.Database }

func (s *mongoStore) GetIdentity(ctx context.Context, factory func() any, id any) (any, error) {
    ident := factory()
    err := s.db.Collection("identities").FindOne(ctx, bson.M{"_id": id}).Decode(ident)
    return ident, err
}
// ... the rest of domain.Storage
```

Prove it behaves like the bundled adapters:

```go
func TestMongoStore(t *testing.T) {
    kayantesting.StorageSuite(t, func() domain.Storage {
        return newMongoStore(testDatabase(t))
    })
}
```

`StorageSuite` is the contract, not a smoke test. It covers every method and
asserts behavior the rest of Kayan depends on — that an expired token is
reported as not found, that deleting a session also removes its refresh-token
index, that `FindIdentity` requires every field in the query to match.

It found a real bug in the GORM adapter the first time it ran: `GetToken`
returned auth tokens past their expiry. Those tokens authenticate password
recovery and magic-link login.

See [Storage Layer](../architecture/storage-layer.md) for the full contract.

---

## What BYOS does not give you

**Kayan does not migrate your schema.** `AutoMigrateDev` builds tables from
your models for development; production uses the versioned SQL in
`gormstore.Migrations()`. Your table is yours to evolve.

**Kayan does not validate your traits.** Supply an `identity.Schema` if you
want trait validation; there is no built-in schema language, because the
shape of your profile data is not something a library can guess.

**Kayan does not know your relationships.** If `orders.user_id` references
your users table, that foreign key is yours to declare. Kayan never sees it —
which is the point, since it also cannot break it.

---

## Related

- [Storage Layer](../architecture/storage-layer.md) — the full `domain.Storage` contract
- [Strategies](./strategies.md) — how authentication methods use your model
- [core reference](../reference/core.md) — `domain` and `identity` in full
