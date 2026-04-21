---
name: senior-go-engineer
description: 'Apply senior Go engineer standards when writing, reviewing, or refactoring Go code. Use when implementing new packages, reviewing code quality, adding tests, fixing error handling, improving concurrency safety, or auditing dependency hygiene. Covers idiomatic Go, interface design, error handling, context propagation, race-safe concurrency, table-driven testing, module hygiene, and Kayan-specific patterns (non-generic architecture, BYOS, strategy/manager, multi-module workspace).'
argument-hint: 'The file, package, or task to write or review as a senior Go engineer (e.g., "review core/flow/login.go", "implement session cleanup job")'
user-invocable: true
---

# Senior Go Engineer

Apply the judgment and standards of a senior Go engineer to writing, reviewing, or refactoring code in this repository.

## When to Use

- Writing a new package, file, or function from scratch
- Reviewing existing Go code for quality, correctness, and idiom
- Refactoring a package to improve clarity, testability, or performance
- Adding or fixing tests (unit, integration, table-driven)
- Auditing error handling, concurrency, or security posture
- Checking module hygiene (`go.mod`, `go.work`, dependency graph)

## What This Skill Produces

- Idiomatic, production-quality Go code matching existing repository conventions
- Correct interface design following the consumer-defined interface principle
- Proper error wrapping with sentinel errors where consumers need them
- Context-propagating function signatures at system boundaries
- Thread-safe implementations verified with `-race`
- Table-driven tests with clear case names and edge coverage
- A review summary (if reviewing) listing findings by severity: **Critical → Important → Minor**

## Repository-Specific Constraints

Always enforce these Kayan rules — they override generic Go idioms where they conflict:

| Rule | Detail |
|------|--------|
| **No generics** | Do not use type parameters `[T any]`. Use `any` + type assertions + factory functions. |
| **BYOS** | Never force struct fields or table names. Use `MapFields` for reflection-based access. |
| **Consumer-defined interfaces** | Define interfaces in the consuming package, not in the implementing package. |
| **Dependency direction** | `core/identity` → no internal deps. `core/flow` may only import `core/domain`, `core/identity`, `core/audit`, `core/events`. Adapters (`kgorm/`, `kredis/`) never imported by `core/`. |
| **Multi-module workspace** | Always `cd` into the module before running `go test`, `go build`, or `go mod tidy`. Never run from workspace root. |
| **Strategy ID strings** | Lowercase, alphanumeric with underscores: `"password"`, `"magic_link"`. |
| **Audit events** | All manager flows must emit audit events for both success and failure via `if auditStore != nil`. |

## Procedure

### 1. Read Before Writing

- Read the file(s) and surrounding package before making any change.
- Identify the package's responsibility and its place in the dependency graph.
- Check the relevant interfaces in `core/domain/storage.go`, `core/flow/flow.go`, or the target package's `types.go`.

### 2. Apply Idiomatic Go Standards

**Naming**
- Exported names: `PascalCase`. Unexported: `camelCase`.
- Acronyms stay uppercase: `HTTP`, `ID`, `URL`, `MFA`.
- Receivers: 1-2 letter abbreviations consistent within a type (`m` for `Manager`, `s` for `Strategy`).
- Avoid redundant package prefixes: `flow.Strategy`, not `flow.FlowStrategy`.

**Package organization**
- One responsibility per package.
- Keep `types.go` for type definitions and constants; `errors.go` for sentinel errors.
- Primary file carries the package doc comment.

**Function signatures**
- `context.Context` is the **first** parameter for anything that calls external services, databases, or needs cancellation.
- Return `error` as the **last** return value.
- Prefer returning concrete types from constructors; return interfaces from factories.

**Constructors**
```go
// Required deps as positional args; optional config via functional options
func NewManager(store Store, opts ...ManagerOption) *Manager

type ManagerOption func(*Manager)
func WithHooks(h Hooks) ManagerOption { return func(m *Manager) { m.hooks = h } }
```

### 3. Enforce Error Handling

- Wrap errors with package prefix: `fmt.Errorf("flow: authenticate: %w", err)`.
- Define sentinel errors for conditions consumers must branch on:
  ```go
  var ErrMFARequired = errors.New("login: mfa required")
  ```
- Never expose internal error details to HTTP response bodies.
- Do not swallow errors with `_` unless the intent is explicitly documented.

### 4. Enforce Context Propagation

- Pass `ctx` through the call stack to storage, external APIs, and audit calls.
- Do not store `context.Context` in structs.
- Respect cancellation: check `ctx.Err()` before and after expensive operations.

### 5. Enforce Concurrency Safety

- Use `sync.RWMutex` for strategy maps and any shared mutable state in managers.
- Prefer `RLock/RUnlock` for reads, `Lock/Unlock` for writes.
- Never share channels across goroutines without explicit ownership.
- All code must pass `go test -race` — this is non-negotiable.

**Manager thread-safety pattern:**
```go
type Manager struct {
    mu         sync.RWMutex
    strategies map[string]Strategy
}

func (m *Manager) Register(s Strategy) {
    m.mu.Lock()
    defer m.mu.Unlock()
    m.strategies[s.ID()] = s
}

func (m *Manager) get(id string) (Strategy, bool) {
    m.mu.RLock()
    defer m.mu.RUnlock()
    s, ok := m.strategies[id]
    return s, ok
}
```

### 6. Write Table-Driven Tests

Every new strategy, manager, or storage adapter must have tests. Structure:

```go
func TestMyFunction(t *testing.T) {
    cases := []struct {
        name    string
        input   InputType
        want    WantType
        wantErr error
    }{
        {name: "success case", ...},
        {name: "missing field", ..., wantErr: ErrSomething},
        {name: "empty input", ...},
    }

    for _, tc := range cases {
        t.Run(tc.name, func(t *testing.T) {
            // arrange
            // act
            // assert
            if tc.wantErr != nil {
                if !errors.Is(err, tc.wantErr) {
                    t.Errorf("got %v, want %v", err, tc.wantErr)
                }
                return
            }
            // positive assertions
        })
    }
}
```

- Use mock interfaces (defined in `_test.go`), never concrete storage.
- Integration tests use `//go:build integration` and require `DATABASE_URL`.
- Run tests with: `cd <module> && go test -race ./...`

### 7. Apply Security Standards

| Concern | Requirement |
|---------|-------------|
| Passwords | `bcrypt` or `argon2` only — never MD5, SHA-1, SHA-256 |
| Token comparison | `subtle.ConstantTimeCompare` for timing safety |
| JWT secrets | Accept via configuration, never hardcoded |
| OIDC state | Cryptographically random, validated on callback |
| OAuth2 | Always use PKCE (`code_challenge`/`code_verifier`) |
| Logging | Never log passwords, tokens, or hashed secrets |
| HTTP responses | Return generic messages — never raw internal errors |

### 8. Audit Module Hygiene

- Verify `go.mod` has the correct `require` and `replace` directives.
- For new modules: add to `go.work` via `go work use ./newmodule`.
- `kredis/go.mod` uses `replace github.com/getkayan/kayan/core => ../core` — new adapters must do the same.
- `kgorm/go.mod` relies on `go.work` for resolution — no replace needed.
- Run `go mod tidy` in the affected module after any dependency change.

### 9. Code Review Checklist

When reviewing existing code, report findings at three severity levels:

**Critical** (must fix before merge)
- [ ] Data race possible (missing mutex, shared state)
- [ ] Error swallowed silently
- [ ] Hardcoded secret or credential
- [ ] Insecure hash (MD5/SHA-1 for passwords)
- [ ] Dependency direction violated (e.g., `core/` imports `kgorm/`)
- [ ] Generics used (type parameters)
- [ ] Test missing for new logic

**Important** (should fix)
- [ ] Context not propagated
- [ ] Error not wrapped with package prefix
- [ ] Sentinel error missing for handleable condition
- [ ] Mutex not used for shared map in manager
- [ ] `go test -race` would fail
- [ ] Package doc comment missing

**Minor** (fix opportunistically)
- [ ] Naming doesn't follow Go conventions
- [ ] Redundant package prefix in type name
- [ ] Unexported field with exported getter/setter that could be a direct field
- [ ] `go mod tidy` would change the module file

## Quality Gates

Before considering any implementation complete:

- [ ] `cd <module> && go build ./...` passes with no errors
- [ ] `cd <module> && go test -race ./...` passes with no failures
- [ ] No linter violations: `golangci-lint run` (run in `core/`)
- [ ] Dependency direction is not violated
- [ ] New exported symbols have doc comments
- [ ] Audit events emitted for all manager success/failure paths
- [ ] No generics introduced
