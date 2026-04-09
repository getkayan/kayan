---
trigger: always_on
---


## 8. Architecture Decision Records

| Decision | Rationale |
|----------|-----------|
| Non-generic design | Supports any ID type without compile-time constraints. Trades compile-time safety for universal compatibility. |
| `any`-based interfaces | Enables BYOS — users keep their models, Kayan adapts with reflection. |
| Strategy pattern | Allows mixing auth methods without modifying core logic. New methods = new files, not modified files. |
| Separate adapter repos | `kgorm/` is co-located but self-contained. Future adapters (MongoDB, Redis) follow the same pattern. |
| Consumer-defined interfaces | Interfaces are declared where they're consumed, not where they're implemented. Follows Go best practices. |
| Hook system over inheritance | Pre/post hooks on managers instead of subclassing. Keeps the API surface flat and composable. |

---
