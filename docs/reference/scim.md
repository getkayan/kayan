# SCIM 2.0

```go
import (
    scim "github.com/getkayan/kayan/kayan-scim"
    "github.com/getkayan/kayan/kayan-scim/gormstore"
)
```

`kayan-scim` implements SCIM 2.0 provisioning (RFC 7643 and RFC 7644): the
protocol Okta, Entra ID, and other identity providers use to create, update,
deactivate, and delete accounts in your application without anyone signing in.
It provides the resource types, a PATCH implementation, a filter parser that
produces an abstract syntax tree rather than backend-specific query text, and a
mapper that projects SCIM resources onto your own identity model. As everywhere
in Kayan, it has no router: the shape is bytes in, validated struct out.

The single most important operation in a provisioning integration is
deprovisioning, and it arrives as a PATCH. Both Okta and Entra ID disable an
account by sending `replace` on the `active` attribute rather than by sending
`DELETE`, so a server without PATCH silently leaves departed employees enabled
while reporting success to the identity provider. The `PatchOp` section below
includes the exact payloads both products send.

---

## Manager

```go
type Manager struct {
    // Has unexported fields.
}

func NewManager(storage ScimStorage, mapper *Mapper) *Manager
```

`Manager` orchestrates SCIM operations over a storage implementation and a
mapper. It is the layer your HTTP handlers call.

```go
func (m *Manager) CreateUser(ctx context.Context, user *User) (*User, error)
func (m *Manager) GetUser(ctx context.Context, id string) (*User, error)
func (m *Manager) UpdateUser(ctx context.Context, id string, user *User) (*User, error)
func (m *Manager) DeleteUser(ctx context.Context, id string) error
func (m *Manager) ListUsers(ctx context.Context, filter string, startIndex, count int) (*ListResponse, error)

func (m *Manager) CreateGroup(ctx context.Context, group *Group) (*Group, error)
func (m *Manager) GetGroup(ctx context.Context, id string) (*Group, error)
func (m *Manager) UpdateGroup(ctx context.Context, id string, group *Group) (*Group, error)
func (m *Manager) DeleteGroup(ctx context.Context, id string) error
func (m *Manager) ListGroups(ctx context.Context, filter string, startIndex, count int) (*ListResponse, error)
```

The `filter` argument is raw SCIM filter text taken from the `filter` query
parameter. `startIndex` is 1-based, as SCIM specifies, not 0-based.

```go
type ListResponse struct {
    Schemas      []string `json:"schemas"`
    TotalResults int      `json:"totalResults"`
    ItemsPerPage int      `json:"itemsPerPage"`
    StartIndex   int      `json:"startIndex"`
    Resources    []any    `json:"Resources"`
}
```

`TotalResults` is the count of matching resources, not the size of this page,
which is what a client needs to know whether to request another page.

---

## ScimStorage

```go
type ScimStorage interface {
    // User operations
    CreateScimUser(ctx context.Context, user *User) error
    GetScimUser(ctx context.Context, id string) (*User, error)
    FindScimUserByUserName(ctx context.Context, userName string) (*User, error)
    UpdateScimUser(ctx context.Context, user *User) error
    DeleteScimUser(ctx context.Context, id string) error
    ListScimUsers(ctx context.Context, filter string, startIndex, count int) ([]*User, int, error)

    // Group operations
    CreateScimGroup(ctx context.Context, group *Group) error
    GetScimGroup(ctx context.Context, id string) (*Group, error)
    UpdateScimGroup(ctx context.Context, group *Group) error
    DeleteScimGroup(ctx context.Context, id string) error
    ListScimGroups(ctx context.Context, filter string, startIndex, count int) ([]*Group, int, error)
}
```

The persistence contract. `kayan-scim/gormstore` is one implementation; a Mongo
adapter, a filesystem adapter, or a call out to an internal provisioning service
satisfies the same interface and drops in without changes elsewhere.

Implementers must guarantee:

**Filters narrow, or fail.** The list methods return `(resources, total, error)`.
If your implementation cannot evaluate the supplied filter, it must return
`ErrFilterUnsupported` rather than ignoring the filter and returning every
resource. A caller that filtered a list expects a subset, and silently widening
it discloses resources they did not ask for. In a multi-tenant deployment, "did
not ask for" can mean "belongs to another customer."

**The second return value is the total, not the page size.** Returning
`len(resources)` makes every response look like the last page, so an identity
provider stops paginating after the first one and considers the remaining users
absent — which, in a deprovisioning reconciliation, means it decides they were
already removed.

**Not found is an error.** `GetScimUser` must return an error for an unknown ID,
conventionally `ErrNotFound`, rather than a nil user and a nil error.

**Uniqueness is enforced.** `userName` is the SCIM correlation key.
`CreateScimUser` for an existing `userName` should return `ErrConflict`, which
maps to HTTP 409; the identity provider then retries as an update rather than
creating a duplicate account.

---

## Resource types

### Resource and Meta

```go
type Resource struct {
    Schemas    []string `json:"schemas"`
    ID         string   `json:"id,omitempty"`
    ExternalID string   `json:"externalId,omitempty"`
    Meta       Meta     `json:"meta,omitempty"`
}

type Meta struct {
    ResourceType string    `json:"resourceType,omitempty"`
    Created      time.Time `json:"created,omitempty"`
    LastModified time.Time `json:"lastModified,omitempty"`
    Location     string    `json:"location,omitempty"`
    Version      string    `json:"version,omitempty"`
}
```

`Resource` is embedded by `User` and `Group`. `ID` is assigned by your service;
`ExternalID` is the identity provider's own identifier for the same person, and
is the field that survives a `userName` change — an employee who marries and
changes their email keeps the same `externalId`.

`Meta.Version` is the ETag for optimistic concurrency. `Meta.Location` is the
canonical URL of the resource, which the library cannot compute because it does
not know your routes.

### User

```go
type User struct {
    Resource
    UserName          string         `json:"userName"`
    Name              *Name          `json:"name,omitempty"`
    DisplayName       string         `json:"displayName,omitempty"`
    NickName          string         `json:"nickName,omitempty"`
    ProfileURL        string         `json:"profileUrl,omitempty"`
    Title             string         `json:"title,omitempty"`
    UserType          string         `json:"userType,omitempty"`
    PreferredLanguage string         `json:"preferredLanguage,omitempty"`
    Locale            string         `json:"locale,omitempty"`
    Timezone          string         `json:"timezone,omitempty"`
    Active            bool           `json:"active"`
    Password          string         `json:"password,omitempty"`
    Emails            []MultiValued  `json:"emails,omitempty"`
    PhoneNumbers      []MultiValued  `json:"phoneNumbers,omitempty"`
    Ims               []MultiValued  `json:"ims,omitempty"`
    Photos            []MultiValued  `json:"photos,omitempty"`
    Addresses         []Address      `json:"addresses,omitempty"`
    Groups            []MemberRef    `json:"groups,omitempty" scim:"readonly"`
    Entitlements      []MultiValued  `json:"entitlements,omitempty"`
    Roles             []MultiValued  `json:"roles,omitempty"`
    Certificates      []MultiValued  `json:"x509Certificates,omitempty"`
    ExtensionSchema   map[string]any `json:"-"`
}

func NewUser() *User
```

`Active` carries no `omitempty`, deliberately. A deprovisioning PATCH sets it to
`false`, and `omitempty` would omit exactly that value from every serialized
response, making a disabled user indistinguishable from an enabled one on the
wire.

`Groups` is tagged `scim:"readonly"`. Group membership is managed through the
`Group` resource, so a PATCH against `groups` on a user is refused rather than
silently ignored — a caller must not believe it changed a membership that in
fact stayed put.

`Password` is write-only in SCIM's model: it may arrive on a create or a PATCH,
and must never be returned. Your handler is responsible for clearing it before
serializing a response, and for hashing it before it reaches storage. `Manager`
does not hash it for you, because password hashing belongs to `domain.Hasher` in
your application's configuration.

`ExtensionSchema` is tagged `json:"-"` and holds decoded schema extensions, such
as the enterprise user extension carrying `manager` and `department`.

### Name, MultiValued, and Address

```go
type Name struct {
    Formatted       string `json:"formatted,omitempty"`
    FamilyName      string `json:"familyName,omitempty"`
    GivenName       string `json:"givenName,omitempty"`
    MiddleName      string `json:"middleName,omitempty"`
    HonorificPrefix string `json:"honorificPrefix,omitempty"`
    HonorificSuffix string `json:"honorificSuffix,omitempty"`
}

type MultiValued struct {
    Value   string `json:"value,omitempty"`
    Display string `json:"display,omitempty"`
    Type    string `json:"type,omitempty"`
    Primary bool   `json:"primary,omitempty"`
    Ref     string `json:"$ref,omitempty"`
}

type Address struct {
    Type          string `json:"type,omitempty"`
    StreetAddress string `json:"streetAddress,omitempty"`
    Locality      string `json:"locality,omitempty"`
    Region        string `json:"region,omitempty"`
    PostalCode    string `json:"postalCode,omitempty"`
    Country       string `json:"country,omitempty"`
    Formatted     string `json:"formatted,omitempty"`
    Primary       bool   `json:"primary,omitempty"`
}
```

`MultiValued` is the shape SCIM uses for every attribute a person can have
several of. `Type` distinguishes them (`work`, `home`, `mobile`) and `Primary`
marks the canonical one. This is why paths like `emails[type eq "work"].value`
exist: there is no single email field to address.

### Group

```go
type Group struct {
    Resource
    DisplayName string      `json:"displayName"`
    Members     []MemberRef `json:"members,omitempty"`
}

func NewGroup() *Group

type MemberRef struct {
    Value   string `json:"value"`
    Ref     string `json:"$ref,omitempty"`
    Type    string `json:"type,omitempty"` // User, Group
    Display string `json:"display,omitempty"`
}
```

`MemberRef.Value` is the member's resource ID. `Type` distinguishes a user
member from a nested group.

### Schema URNs

```go
const (
    UserSchema  = "urn:ietf:params:scim:schemas:core:2.0:User"
    GroupSchema = "urn:ietf:params:scim:schemas:core:2.0:Group"
)

const PatchOpSchema = "urn:ietf:params:scim:api:messages:2.0:PatchOp"
```

---

## Mapper

```go
type Mapper struct {
    // Has unexported fields.
}

func NewMapper(factory func() any, config MapperConfig) *Mapper

func (m *Mapper) ToModel(user *User) (any, error)
func (m *Mapper) FromModel(model any) (*User, error)
func (m *Mapper) ToModelPlaceholder() any
func (m *Mapper) Config() MapperConfig
```

```go
type MapperConfig struct {
    // FieldMappings maps SCIM field paths to struct field names.
    // Example: "userName" -> "Email"
    FieldMappings map[string]string

    // TraitMappings maps SCIM field paths to keys in the Traits JSON.
    // Example: "name.givenName" -> "first_name"
    TraitMappings map[string]string
}
```

The mapper is the BYOS seam for provisioning. Kayan has no user table and no
reserved column names, so it cannot know that a SCIM `userName` is your `Email`
column, or that `name.givenName` lives inside a JSON traits blob rather than in
a column of its own. `NewMapper` takes a factory returning a fresh instance of
your struct and a configuration describing where each SCIM attribute goes.

```go
mapper := scim.NewMapper(
    func() any { return &User{} },
    scim.MapperConfig{
        FieldMappings: map[string]string{
            "userName":    "Email",
            "displayName": "DisplayName",
            "active":      "Active",
        },
        TraitMappings: map[string]string{
            "name.givenName":  "first_name",
            "name.familyName": "last_name",
            "title":           "job_title",
        },
    },
)
```

`FieldMappings` targets Go struct field names, not database column names —
resolution is by reflection over the struct returned by the factory. A mapping
naming a field that does not exist is a configuration error you discover on the
first request, so exercise the mapper in a test.

`ToModelPlaceholder` returns an empty instance of the target model, which
storage adapters use to derive table and column names.

---

## PATCH

### PatchOp and PatchOperation

```go
type PatchOp struct {
    Schemas    []string         `json:"schemas"`
    Operations []PatchOperation `json:"Operations"`
}

type PatchOperation struct {
    Op    string          `json:"op"`
    Path  string          `json:"path,omitempty"`
    Value json.RawMessage `json:"value,omitempty"`
}

const (
    PatchOpAdd     = "add"
    PatchOpRemove  = "remove"
    PatchOpReplace = "replace"
)
```

PATCH is how identity providers deprovision: Okta and Entra ID both deactivate a
user by sending `replace` on the `active` attribute rather than deleting the
resource. A provisioning integration without PATCH silently fails to disable
anyone.

`Value` is `json.RawMessage` rather than `any` because the correct
interpretation depends on the path. Decoding eagerly into `any` turns `false`
into a `bool` and `"False"` into a `string`, and the difference matters: one is
a valid deprovisioning instruction and the other is a malformed request that
must be refused rather than guessed at.

### ParsePatchOp

```go
func ParsePatchOp(data []byte) (*PatchOp, error)
```

Decodes and validates a SCIM PATCH request body. It rejects, with a
`*ErrorResponse` carrying HTTP status 400 and a `scimType`:

- an empty body (`invalidSyntax`);
- malformed JSON (`invalidSyntax`);
- a `schemas` array not containing `PatchOpSchema` (`invalidSyntax`);
- an empty `Operations` array (`invalidValue`);
- more than `MaxPatchOperations` operations (`tooMany`);
- `add` or `replace` with no value (`invalidValue`);
- `remove` with no path (`noTarget`);
- an unknown operation name (`invalidValue`);
- a path that does not parse.

Operation names are lowercased and trimmed before comparison, because SCIM
operation names are case-insensitive and Entra ID sends `"Replace"` with a
capital R. A parser that compared exactly would reject every Entra ID
deprovisioning request.

`remove` without a path is refused rather than interpreted, because a path-less
remove would delete the entire resource.

### MaxPatchOperations and MaxFilterDepth

```go
const MaxPatchOperations = 100
```

Bounds how many operations one request may carry. The endpoint is authenticated
but the body is still attacker-supplied, and each operation costs a reflective
walk of the resource.

```go
const MaxFilterDepth = 20
```

Bounds nesting in a filter. The filter arrives as a query parameter, so a deeply
nested expression would otherwise be a cheap way to exhaust the stack — the
parser is recursive descent, and unbounded recursion on attacker input is a
crash, not a rejection. Exceeding the limit returns `ErrInvalidFilter`.

Both limits fail closed: the request is refused rather than truncated. A
truncated PATCH would apply some operations and not others, leaving the resource
in a state neither side expects.

### ApplyPatch

```go
func ApplyPatch(user *User, patch *PatchOp) (*User, error)
```

Applies a PATCH request to a user and returns the result. **The input is not
modified** — the returned user is a new value, so a failed operation partway
through a multi-operation patch leaves the caller's original intact rather than
half-updated.

Read-only attributes are refused rather than silently ignored, with a
`mutability` error, so a caller cannot believe it changed an ID that in fact
stayed put. Silent ignoring is the worse failure: the identity provider records
the change as applied and never retries.

The read-only set is `id`, `meta`, `groups`, and `schemas` (RFC 7643 section
3.1). `id` and `meta` are server-assigned, `schemas` describes the resource
rather than being part of it, and `groups` is a projection of group membership
managed through the `Group` resource — a PATCH that appeared to add a group
membership on the user would grant nothing, so it is refused.

An operation with no path replaces whole attributes from an object value, which
is how some clients set several fields at once — Okta's deprovisioning payload
below is exactly that shape. A path-less operation therefore requires an object
value; a scalar is refused with `invalidValue`, since there is no attribute to
apply it to.

### Real deprovisioning payloads

These are the exact bodies Okta and Entra ID send to disable an account, and
both are covered by the module's tests.

**Okta** sends no path and an object value:

```json
{
  "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
  "Operations": [{"op": "replace", "value": {"active": false}}]
}
```

**Entra ID** sends a path, a scalar value, and a capitalized operation name:

```json
{
  "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
  "Operations": [{"op": "Replace", "path": "active", "value": false}]
}
```

Both must work, and both do. Supporting only one of these shapes means one of
the two largest identity providers cannot deprovision through your integration,
and it will not tell you — the request succeeds and the account stays enabled.

A third shape appears in the wild and is deliberately **refused**:

```json
{
  "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
  "Operations": [{"op": "replace", "path": "active", "value": "False"}]
}
```

The string `"False"` is not valid JSON for a boolean. It is rejected with
`invalidValue` rather than coerced, because coercing it means deciding what
`"false"`, `"0"`, and `""` mean, and every such decision is a way for an
enable request to be read as a disable request or the reverse.

Applying a patch:

```go
patch, err := scim.ParsePatchOp(body)
if err != nil {
    var serr *scim.ErrorResponse
    if errors.As(err, &serr) {
        writeSCIMError(w, serr) // serr.Status is the HTTP status as a string.
    }
    return
}

user, err := manager.GetUser(ctx, id)
if err != nil {
    return
}

updated, err := scim.ApplyPatch(user, patch)
if err != nil {
    return
}

if _, err := manager.UpdateUser(ctx, id, updated); err != nil {
    return
}
```

---

## Paths

```go
type Path struct {
    // Attribute is the top-level attribute, such as "emails" or "active".
    Attribute string

    // Filter selects among a multi-valued attribute's entries. Nil when the
    // path carries no filter.
    Filter FilterExpr

    // SubAttribute addresses a member of the selected value, such as the
    // "value" in emails[...].value.
    SubAttribute string

    // URN is the schema extension the attribute belongs to, if the path was
    // fully qualified.
    URN string
}

func ParsePath(path string) (Path, error)
func (p Path) String() string
```

SCIM paths address more than a field name: `emails[type eq "work"].value`
selects the `value` sub-attribute of whichever email has type `work`.

### The path grammar

Accepted forms:

```
active
name.givenName
emails[type eq "work"].value
urn:ietf:params:scim:schemas:extension:enterprise:2.0:User:manager
```

Informally:

```
path        = [ urn ":" ] attribute [ "[" filter "]" ] [ "." subAttribute ]
urn         = "urn:" 1*( segment ":" ) segment
attribute   = ALPHA *( ALPHA / DIGIT / "_" / "-" )
subAttribute= attribute
filter      = a SCIM filter expression, as accepted by ParseFilter
```

The four forms map onto the struct directly:

| Path text | `Attribute` | `Filter` | `SubAttribute` | `URN` |
|---|---|---|---|---|
| `active` | `active` | nil | `""` | `""` |
| `name.givenName` | `name` | nil | `givenName` | `""` |
| `emails[type eq "work"].value` | `emails` | `Comparison{type eq "work"}` | `value` | `""` |
| `urn:...:enterprise:2.0:User:manager` | `manager` | nil | `""` | `urn:...:enterprise:2.0:User` |

The URN prefix is what disambiguates an extension attribute from a core one:
`manager` in the enterprise extension is a different attribute from a `manager`
someone defined in a custom schema, and the path grammar is the only place that
distinction is expressible.

`String` renders a parsed path back to SCIM syntax, which round-trips.

A path that does not parse is an error, not a fallback to treating the whole
string as an attribute name. Treating `emails[type eq "work"]` as an attribute
literally named `emails[type eq "work"]` would find nothing, and a PATCH against
nothing that reports success is a silent failure to provision.

---

## Filters

```go
type FilterExpr interface {
    // String renders the expression back to SCIM filter syntax.
    String() string

    // Has unexported methods.
}
```

`FilterExpr` is a node in a parsed SCIM filter. The filter is parsed to a tree
rather than to backend-specific query text, so it stays independent of both
transport and storage: a GORM adapter walks it into a `WHERE` clause, a Mongo
adapter into a BSON document, and neither needs a parser of its own.

The unexported method makes the interface closed. Only this package can add node
types, so a storage adapter's type switch over the four concrete types is
exhaustive and stays exhaustive.

Producing an AST rather than SQL text is also the reason filter values cannot
reach the SQL grammar. There is no stage at which a filter is a string being
concatenated into a query.

```go
type Comparison struct {
    Path     Path
    Operator string
    // Value is nil for the "pr" (present) operator, which takes no operand.
    Value any
}

type And struct{ Left, Right FilterExpr }
type Or  struct{ Left, Right FilterExpr }
type Not struct{ Expr FilterExpr }

func (c Comparison) String() string
func (a And) String() string
func (o Or) String() string
func (n Not) String() string
```

### ParseFilter

```go
func ParseFilter(filter string) (FilterExpr, error)
```

Parses a SCIM filter expression (RFC 7644 section 3.4.2.2).

```
userName eq "bjensen"
name.familyName co "O'Malley"
emails[type eq "work" and value co "@example.com"]
title pr and userType eq "Employee"
not (userType eq "Employee")
```

Nesting deeper than `MaxFilterDepth` returns `ErrInvalidFilter`.

### The operator set

```go
const (
    OpEqual              = "eq"
    OpNotEqual           = "ne"
    OpContains           = "co"
    OpStartsWith         = "sw"
    OpEndsWith           = "ew"
    OpPresent            = "pr"
    OpGreaterThan        = "gt"
    OpGreaterThanOrEqual = "ge"
    OpLessThan           = "lt"
    OpLessThanOrEqual    = "le"
)
```

| Operator | Constant | Meaning |
|---|---|---|
| `eq` | `OpEqual` | Attribute equals the operand. |
| `ne` | `OpNotEqual` | Attribute does not equal the operand. |
| `co` | `OpContains` | Attribute contains the operand as a substring. |
| `sw` | `OpStartsWith` | Attribute begins with the operand. |
| `ew` | `OpEndsWith` | Attribute ends with the operand. |
| `pr` | `OpPresent` | Attribute is present and non-empty. Takes no operand, so `Comparison.Value` is nil. |
| `gt` | `OpGreaterThan` | Attribute is greater than the operand. |
| `ge` | `OpGreaterThanOrEqual` | Attribute is greater than or equal to the operand. |
| `lt` | `OpLessThan` | Attribute is less than the operand. |
| `le` | `OpLessThanOrEqual` | Attribute is less than or equal to the operand. |

`pr` is the operator to handle specially in a storage adapter: it is the only one
where `Value` is nil, and a walk that assumes an operand dereferences nil.

Precedence follows the specification: `not` binds tightest, then `and`, then
`or`. Parentheses group.

---

## Errors

```go
var (
    ErrNotFound      = errors.New("scim: resource not found")
    ErrInvalidFilter = errors.New("scim: invalid filter")
    ErrUnsupported   = errors.New("scim: operation not supported")
    ErrConflict      = errors.New("scim: resource already exists")

    ErrFilterUnsupported = errors.New("scim: filtering is not supported by this storage implementation")
)
```

| Sentinel | Conventional HTTP status | Meaning |
|---|---|---|
| `ErrNotFound` | 404 | The resource does not exist. |
| `ErrInvalidFilter` | 400 | The filter is malformed or exceeds `MaxFilterDepth`. |
| `ErrUnsupported` | 501 | The operation is not implemented. |
| `ErrConflict` | 409 | A resource with this `userName` already exists. |
| `ErrFilterUnsupported` | 400 | This storage implementation cannot evaluate the filter. |

`ErrFilterUnsupported` is the one an implementer must not skip. Implementations
must return it rather than ignoring the filter and returning every resource: a
caller that filtered a list expects a subset, and silently widening it discloses
resources they did not ask for. Refusing a query the backend cannot answer is a
visible failure that gets fixed; answering a different question than the one
asked is not.

`ErrConflict` mapping to 409 is what lets an identity provider recover. Okta
treats 409 on create as a signal to look up the existing resource and update it
instead, so a correct conflict response turns a duplicate-account bug into a
successful reconciliation.

### ErrorResponse

```go
type ErrorResponse struct {
    Schemas  []string `json:"schemas"`
    Status   string   `json:"status"`
    ScimType string   `json:"scimType,omitempty"`
    Detail   string   `json:"detail"`
}

func NewError(status, scimType, detail string) *ErrorResponse
func (e *ErrorResponse) Error() string
```

The SCIM error response format from RFC 7644 section 3.12. `NewError` fills
`Schemas` with `urn:ietf:params:scim:api:messages:2.0:Error`.

`Status` is the HTTP status as a string, which is how SCIM defines it — `"400"`,
not `400`. `ScimType` is the machine-readable sub-code that tells the identity
provider *why*: `invalidSyntax`, `invalidValue`, `invalidPath`, `noTarget`,
`mutability`, `tooMany`, `invalidFilter`, `uniqueness`.

`ScimType` is worth populating correctly rather than defaulting everything to
`invalidValue`. Identity providers branch on it: `mutability` tells Okta the
attribute will never be writable and to stop sending it, while `invalidValue`
tells it the value was wrong and to retry with a different one.

`ParsePatchOp` and `ApplyPatch` return `*ErrorResponse` directly, so a handler
can extract it with `errors.As` and serve it verbatim:

```go
var serr *scim.ErrorResponse
if errors.As(err, &serr) {
    status, _ := strconv.Atoi(serr.Status)
    w.Header().Set("Content-Type", "application/scim+json")
    w.WriteHeader(status)
    json.NewEncoder(w).Encode(serr)
    return
}
```

---

## Package `gormstore`

```go
import "github.com/getkayan/kayan/kayan-scim/gormstore"
```

Persists SCIM resources with GORM. It is one implementation of
`scim.ScimStorage`. Any other backend — Mongo, a filesystem, a bespoke service —
satisfies the same interface and drops in without changes elsewhere.

```go
type ScimRepository struct {
    // Has unexported fields.
}

func NewScimRepository(db *gorm.DB, mapper *scim.Mapper) *ScimRepository
```

The mapper is required, not optional. SCIM users are stored in your own identity
table, not in a table this package owns, so the repository needs the mapper to
know which column a SCIM attribute corresponds to. Groups are stored in a table
this package does own, `scim_groups`.

```go
func (r *ScimRepository) AutoMigrate() error
```

Creates the tables this repository needs. **For development only.** Production
deployments should run versioned migrations; see the module README.

```go
func (r *ScimRepository) CreateScimUser(ctx context.Context, user *scim.User) error
func (r *ScimRepository) GetScimUser(ctx context.Context, id string) (*scim.User, error)
func (r *ScimRepository) FindScimUserByUserName(ctx context.Context, userName string) (*scim.User, error)
func (r *ScimRepository) UpdateScimUser(ctx context.Context, user *scim.User) error
func (r *ScimRepository) DeleteScimUser(ctx context.Context, id string) error
func (r *ScimRepository) ListScimUsers(ctx context.Context, filter string, startIndex, count int) ([]*scim.User, int, error)

func (r *ScimRepository) CreateScimGroup(ctx context.Context, group *scim.Group) error
func (r *ScimRepository) GetScimGroup(ctx context.Context, id string) (*scim.Group, error)
func (r *ScimRepository) UpdateScimGroup(ctx context.Context, group *scim.Group) error
func (r *ScimRepository) DeleteScimGroup(ctx context.Context, id string) error
func (r *ScimRepository) ListScimGroups(ctx context.Context, filter string, startIndex, count int) ([]*scim.Group, int, error)
```

### Filters compile to SQL with bound parameters

The list methods parse the filter with `scim.ParseFilter` and walk the resulting
AST into a GORM `Where` clause. **Every value is bound as a parameter.** The
filter arrives as an AST rather than as text, so this walks a tree instead of
parsing, and there is no point at which request text becomes SQL text.

Column names are resolved through the mapper and never interpolated from the
request, so a filter cannot reach the SQL grammar in either position — neither
through a value nor through an attribute name. Column names are additionally
quoted with embedded quotes doubled, as a second line of defense against a future
code path that forgets where column names come from.

`co`, `sw`, and `ew` compile to `LIKE` with the operand escaped: backslash,
`%`, and `_` are neutralized before the wildcards are added. Without that,
`userName co "%"` matches every row, turning a narrowing filter into a full
listing — which is the disclosure `ErrFilterUnsupported` exists to prevent,
arriving by a different route.

`pr` compiles to `(column IS NOT NULL AND column <> '')`, treating an empty
string as absent, which is what SCIM means by present.

Value filters are refused. A path such as `emails[type eq "work"].value` selects
within a multi-valued attribute, which a relational adapter cannot express
against a scalar column; the repository returns a 400 `invalidFilter` rather than
dropping the inner condition and returning a wider set. Value filters do work in
PATCH, where `ApplyPatch` walks the in-memory resource and can evaluate them.

An unsupported operator or an unrecognized expression type is likewise refused
with `invalidFilter` rather than skipped.

## Stable sorting

```go
type ListOptions struct {
    Filter     string
    StartIndex int
    Count      int
    SortBy     string
    SortOrder  string
}

const (
    SortAscending  = "ascending"
    SortDescending = "descending"
)

func (m *Manager) ListUsersSorted(ctx context.Context, opts ListOptions) (*ListResponse, error)
func (m *Manager) ListGroupsSorted(ctx context.Context, opts ListOptions) (*ListResponse, error)
```

An empty `SortBy` uses the ordinary list path. A requested sort requires the
optional `SortableScimStorage`; otherwise the manager returns
`ErrSortUnsupported` instead of sending an unsorted result that looks valid.
An unmapped attribute returns `ErrInvalidSortAttribute`.

```go
type SortableScimStorage interface {
    SupportsSorting() bool
    ListScimUsersSorted(ctx context.Context, opts ListOptions) ([]*User, int, error)
    ListScimGroupsSorted(ctx context.Context, opts ListOptions) ([]*Group, int, error)
}
```

The GORM adapter resolves `SortBy` through `MapperConfig`; request text never
becomes a SQL identifier. It adds the primary key as a tiebreaker when the
selected column is not unique, keeping pagination stable between pages. Plain
list results are also ordered by ID.

## Resource metadata and ETags

```go
type MapperConfig struct {
    FieldMappings  map[string]string
    TraitMappings  map[string]string
    MetaMappings   map[string]string
    ResourceBaseURL string
}

const (
    MetaCreated      = "created"
    MetaLastModified = "lastModified"
    MetaVersion      = "version"
)
```

Map metadata to fields on the application model:

```go
mapper := scim.NewMapper(func() any { return &User{} }, scim.MapperConfig{
    FieldMappings: map[string]string{
        "id":       "ID",
        "userName": "Email",
    },
    MetaMappings: map[string]string{
        scim.MetaCreated:      "CreatedAt",
        scim.MetaLastModified: "UpdatedAt",
        scim.MetaVersion:      "Version",
    },
    ResourceBaseURL: "https://api.example.com/scim/v2",
})
```

Unmapped timestamps are omitted rather than invented. `ResourceBaseURL` builds
`meta.location`; Kayan cannot infer it because the library owns no router.
Versions are valid ETag strings. A content-derived weak ETag is sufficient for
caching, but not for an atomic `If-Match` write.

## Conditional writes

```go
type ConditionalScimStorage interface {
    SupportsConditionalWrites() bool
    UpdateScimUserIfMatch(ctx context.Context, user *User, ifMatch string) error
    DeleteScimUserIfMatch(ctx context.Context, id, ifMatch string) error
    UpdateScimGroupIfMatch(ctx context.Context, group *Group, ifMatch string) error
    DeleteScimGroupIfMatch(ctx context.Context, id, ifMatch string) error
}

func (m *Manager) UpdateUserIfMatch(ctx context.Context, id string, user *User, ifMatch string) (*User, error)
func (m *Manager) DeleteUserIfMatch(ctx context.Context, id, ifMatch string) error
func (m *Manager) UpdateGroupIfMatch(ctx context.Context, id string, group *Group, ifMatch string) (*Group, error)
func (m *Manager) DeleteGroupIfMatch(ctx context.Context, id, ifMatch string) error
```

These methods require a non-empty `If-Match` value and an atomic storage
implementation. A mismatched version returns `ErrPreconditionFailed`, which the
host serves as HTTP 412. A backend without compare-and-swap returns
`ErrConditionalUnsupported`; the manager never falls back to a racy
read-check-write sequence. The wildcard `*` matches any existing resource.

Use `Manager.ServiceProviderConfig`, not the package-level helper, for discovery:
it advertises sorting and ETag support from the configured storage's actual
capabilities. `ResourceTypes`, `Schemas`, and `Schema` provide the remaining
transport-neutral discovery resources.

---

## Known gaps

Kayan returns discovery resources but remains headless: the host maps them to
`/Schemas`, `/ResourceTypes`, and `/ServiceProviderConfig`. Bulk operations,
`/Me`, `POST /.search`, attribute projection, and password changes are not
implemented. Value filters such as `emails[type eq "work"]` work in PATCH but
not in list queries, for the reason given above.
