# Headless and Backend-Neutral Contract

Kayan owns IAM rules and protocol correctness. The host application owns HTTP
routing, cookies, response rendering, deployment, and its data model.

## Permanent boundaries

- `core` must not import database drivers, ORMs, Redis clients, or third-party
  HTTP frameworks.
- Protocol implementations remain sibling modules so applications compile only
  what they use.
- Managers and strategies accept the smallest consumer-defined interface needed
  for their operation. A composite storage interface is convenience, not a
  requirement.
- Identity models require only `FlowIdentity`; traits and credentials remain
  opt-in capabilities.
- Concrete adapters are optional and interchangeable. No constructor silently
  creates or selects a database, cache, or server backend.
- Protocol packages parse transport-neutral inputs and return transport-neutral
  results. Framework bindings live outside `core` and remain optional.

## Enforcement

CI resolves actual Go imports to enforce module direction. Storage conformance
suites verify behavior without prescribing implementation, schema, table names,
or ID types. Reference adapters run those same suites in addition to tests for
their database-specific behavior.
