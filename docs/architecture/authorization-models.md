# Authorization Models

Kayan intentionally separates authorization models instead of collapsing everything into one catch-all abstraction.

## RBAC Architecture

`core/rbac` is a lightweight role and permission engine. It expects a strategy that knows how to answer questions such as:

- what roles does this identity have?
- does this identity have a role?
- what permissions are implied by those roles or directly attached?

This makes RBAC easy to adapt to:

- roles stored directly on the identity
- roles stored in a separate persistence layer
- derived roles computed from tenant or org membership

Use RBAC for coarse-grained control and admin tooling. Avoid encoding deep hierarchy traversal into flat role strings if your resource model is actually relational.

## ABAC Architecture

`core/policy` exposes an `Engine` interface with a single `Can(ctx, subject, action, resource)` method. That small contract is enough to support:

- pure ABAC strategies
- custom domain-specific engines
- composed hybrid policies

Because rules are ordinary Go functions, they can inspect:

- subject traits
- resource attributes
- tenant context
- request metadata
- device or risk metadata added to context

This is a good fit for service-level authorization where the business rules already live in Go and need strong testability.

## Hybrid Architecture

Hybrid policy is usually the operational sweet spot in complex SaaS systems. The common model is:

- RBAC for broad capability assignment
- ABAC for contextual narrowing

Example:

- role says the actor is a billing admin
- ABAC says they can only see invoices in their tenant and region

Treat hybrid policy as composition, not duplication. Keep one layer responsible for entitlement and the other responsible for context.

## ReBAC Architecture

`core/rebac` models authorization as relationship graph traversal. Its main primitives are typed subject and object references plus relation names. A schema can define:

- direct relations
- computed relations
- tuple-to-userset rewrites
- cross-object inheritance rules

That lets you represent structures such as:

- user belongs to team
- team administers workspace
- workspace owns project
- project contains document
- document viewers inherit from project viewers

The checker includes max-depth and cycle protection to keep graph traversal bounded.

## Choosing a Model

Use RBAC when your rules can be explained as named roles and direct permissions.

Use ABAC when the rule depends on dynamic facts at evaluation time.

Use ReBAC when the rule depends on graph traversal or object hierarchy.

Use hybrid when two of those statements are true at once.

## Recommended Boundaries

- Keep request parsing outside the engine.
- Keep persistence details outside the engine unless the store is explicitly part of the model, as in ReBAC.
- Keep denial semantics simple for callers: boolean plus error.
- Keep explanation, debug traces, or audit annotations as surrounding concern, not as the core authorization result type.