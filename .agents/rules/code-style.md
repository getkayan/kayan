---
trigger: always_on
---

## 5. Code Style Rules

### 5.1 Error Handling
- Return `error` as the last return value.
- Use `fmt.Errorf("package: description: %w", err)` wrapping with package prefix.
- Define sentinel errors for cases consumers need to handle:
  ```go
  var ErrMFARequired = errors.New("login: mfa required")
  ```
- Never expose internal error messages to HTTP responses — use generic messages at the handler layer.

### 5.2 Context Usage
- `context.Context` must be the **first parameter** for any function that:
  - Calls external services or databases
  - May need cancellation or timeout
  - Passes through audit/tenant context
- Strategies, managers, and storage methods must accept `context.Context`.

### 5.3 Constructor Pattern
```go
// Required dependencies as positional args
// Optional config via functional options or setters
func NewManager(store Store, resolver Resolver, opts ...ManagerOption) *Manager

// Option type
type ManagerOption func(*Manager)
func WithHooks(hooks Hooks) ManagerOption { ... }
```

### 5.4 Audit Integration
- All `RegistrationManager` and `LoginManager` flows must emit audit events for both success and failure.
- Audit events must include: `Type`, `ActorID`, `Status`, `Message`.
- Audit is **opt-in**: check `if auditStore != nil` before logging (never panic on missing audit).

---
