---
trigger: always_on
---

## 4. File & Package Conventions

### 4.1 File Naming

| Pattern | Example | Purpose |
|---------|---------|---------|
| `strategy_*.go` | `strategy_password.go` | Auth strategy implementations |
| `*_manager.go` or `manager.go` | `registration.go`, `manager.go` | Manager/orchestrator |
| `*_store.go` or `store.go` | `memory_store.go` | Storage implementations |
| `*_test.go` | `lockout_test.go` | Tests (must match source file) |
| `middleware.go` | `middleware.go` | HTTP middleware |
| `types.go` | `types.go` | Type definitions and constants |
| `checker.go` | `checker.go` | Validation/verification logic |

### 4.2 Package Doc Comments
Every package must have a doc comment in its primary `.go` file with:
- One-line description of purpose
- Subpackage listing (if applicable)
- Usage example in godoc format

### 4.3 New Package Checklist
When adding a new package under `core/`:
1. Create the package directory under `core/`
2. Add a primary file with package doc comment
3. Define interfaces **in the consuming package** (consumer-defined interfaces)
4. Ensure it does not violate dependency rules (Section 2)
5. Add tests (`*_test.go`) — **do not merge untested packages**
6. Update `core/kayan.go` doc comment with the new subpackage
7. Update `docs/architecture/README.md` with the new component

---
