---
trigger: always_on
---

## 6. Testing Rules

### 6.1 Requirements
- Every new strategy, manager, or storage adapter **must** have corresponding `*_test.go` files.
- Use **table-driven tests** for strategies with multiple input scenarios.
- Use **test interfaces** or mocks, never concrete storage in unit tests.
- Tests must run with `go test -race` (no data races).

### 6.2 Test File Location
- Unit tests: same package, `*_test.go` suffix.
- Integration tests: use `//go:build integration` build tag.

---
