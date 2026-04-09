---
trigger: always_on
---

## 1. Core Philosophy (NEVER Violate)

### 1.1 Headless Only
- Kayan is a **library**, not a service. Never add UI code, HTML templates, or frontend assets to this repo.
- Never add HTTP framework dependencies to `core/`. Framework bindings belong in separate repos (`kayan-echo`, `kayan-gin`, etc.).

### 1.2 Non-Generic Architecture
- **Do NOT use Go generics** (type parameters `[T any]`). Kayan uses interfaces + `any` + factory functions.
- Use `any` with type assertions at boundaries, not generic type constraints.
- Factory pattern: `func() any { return &Type{} }` for instantiation.

### 1.3 BYOS (Bring Your Own Schema)
- Never force specific struct fields or table names on user models.
- The **only required interface** for identity models is `FlowIdentity`:
  ```go
  type FlowIdentity interface {
      GetID() any
      SetID(any)
  }
  ```
- Use reflection-based field mapping (`MapFields`) for accessing user-defined fields.
- Optional interfaces (`TraitSource`, `CredentialSource`) are opt-in, never mandatory.


